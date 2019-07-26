# DHCP-Starvation
When in a public network, this script (DHCP starvation) will take all the IPs in a specifc IP range. 

DHCP protocol has 4 steps:
1.	Discover –The client sends a broadcast message to discover servers.
2.	Offer – The DHCP server sends a message back with an IP address available if one exists.
3.	Request – The client requests the IP address.
4.	ACK – The server sends ACK if it approves the request. If it does not approve, it will send NAK.

Explanation about the script:
The program has two main parts. The first part is a thread using the Sniffer class, and the second part is the main process.

1.	The Sniffer() class will give me the ability to sniff packets and analyze the packets. The following is the logic of the class: The class waits for a packet. When a packet arrives, the method “analyze packet” examines if the packet’s IP source is the router address, and if the message is ACK. If the packet arrived is qualified, the program adds the host as a key to the Python dictionary. The Python dictionary cannot have two similar keys, so it will assure that the number of keys in the dictionary will also be numbers of hosts that received ACKs for IP addresses. There are 101 available addresses in the given range, and one of them belongs to Kali Linux. Therefore, I determined that when the number of keys in the dictionary is 100, the program will stop.
2.	The main process builds DHCP requests packets using Scapy module and sends them. When it builds the packets, it uses the last three digits of the IP address as the last three characters of the hardware address (Chaddr), so it easier for the sniffer to analyze the ACKs packets. When the thread from the Sniffer class completes its task, it signals the main process, and the program stops. Also, I added a 100 millisecond delay between each packet transmission to allow more time for the router to process and respond to the requests as was instructed, even though the script works properly without this addition.  


