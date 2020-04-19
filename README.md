# Cloudflare-Internship-Ping-Application
A Ping CLI application for the Cloudflare Workers Internship application

This is a Ping CLI application written in C that supports both IPv4 and IPv6 addresses as well as an optional TTL argument. 
To use the application, run the executable with root privileges and give a hostname or IP address as input. 

Some example commands are as follows:

sudo ./ping google.com\n
sudo ./ping --ttl=54 google.com\n
sudo ./ping 216.58.194.174\n
sudo ./ping 2607:f8b0:4005:802::200e\n

