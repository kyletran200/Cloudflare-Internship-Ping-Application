#include <iostream>
#include <stdio.h>

using namespace std;

int main(int argc, char ** argv) 
{
    /* Our ping app should only accept 1 argument */
    if (argc != 2) {
        cout << "usage: " << argv[0] << " <hostname> or <ip address>" << endl;
        return 0;
    }

    string ip_address = argv[1];
    cout << "This is ip_address: " << ip_address << endl;
}   
