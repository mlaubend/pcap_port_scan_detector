# created by Mark Laubender 4/20/15
#


import sys
import socket
import dpkt

filepath = sys.argv[1]
dictionary = {}

openfile = open(filepath)
pcap = dpkt.pcap.Reader(openfile)

								#main loop gathers necessary data from file
for ts, buf in pcap:
	try:
		eth = dpkt.ethernet.Ethernet(buf) 		#ethernet layer	
		ip = eth.data 					#ip layer
		tcp = ip.data 					#tcp layer
		syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0 #syn flag
		ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0 #ack flag
		srcaddr = socket.inet_ntoa(ip.src) 		#plaintext representation of source ip address
		dstaddr = socket.inet_ntoa(ip.dst) 		# dest. ip address
	except: 						#if we get here, the packet is not tcp/ip and should be ignored
		continue

								#building dictionary
	if srcaddr not in dictionary:
		dictionary[srcaddr] = {'syn':0, 'ack':0}
	if dstaddr not in dictionary:
		dictionary[dstaddr] = {'syn':0, 'ack':0}
	
								#counting and storing flags
	if syn_flag:
		if ack_flag:
			dictionary[dstaddr]['ack'] += 1
		else:
			dictionary[srcaddr]['syn'] += 1

openfile.close()

								#calculating syn to syn/ack ratio and printing
for IP in dictionary:
	try:
		if (dictionary[IP]['syn'] / dictionary[IP]['ack']) >= 3:
			print IP
	except:	
		if dictionary[IP]['syn'] >= 3: 			#division by zero case
			print IP
		

