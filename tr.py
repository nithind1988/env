#!/usr/bin/env python

# Version 16/09/2020

# Need atleast python36
from scapy.all import *
import scapy.contrib.geneve
import time
import ipaddress
import sys
import subprocess
import os
import signal
import difflib
import re
import signal
from subprocess import DEVNULL
from threading import Timer
ethdev_name="enP2p1s0v2"
dutmac = "f2:e1:a8:29:ab:ba"
testermac = "2E:8F:CC:AD:7A:9F"
capture_rx=1
recv_sanity=1
sizeinc = 13
size = 64#7000#7000#128#7000
minsize = size
maxsize = 1300#1400#8512#1400#9000
dump = 0
burst_size = 1
pkt_bursts, flows = (512, 1)
good_checksum=0
inner_checksum_dontcare=0

#default bool opts
opt_dict = {
'ipv4_tcp':1,
'ipv4_udp':1,
'ipv4_sctp':0,
'ipv6_tcp':0,
'ipv6_udp':0,
'ipv6_sctp':0,
'ipv4_gre_ipv4_tcp':0,
'ipv6_gre_ipv4_tcp':0,
'ipv4_gre_ipv6_tcp':0,
'ipv6_gre_ipv6_tcp':0,
'ipv4_vxlan_ipv4_tcp':1,
'ipv6_vxlan_ipv4_tcp':1,
'ipv4_vxlan_ipv6_tcp':1,
'ipv6_vxlan_ipv6_tcp':1,
'ipv4_geneve_ipv4_tcp':1,
'ipv6_geneve_ipv4_tcp':1,
'ipv4_geneve_ipv6_tcp':1,
'ipv6_geneve_ipv6_tcp':1,
'dot1q_ipv4_tcp':1,
'dot1q_ipv6_tcp':1,
'dot1q_ipv4_gre_ipv4_tcp':0,
'dot1ad_dot1q_ipv4_tcp':1,
'dot1ad_dot1q_ipv6_tcp':1,
'dot1ad_dot1q_ipv4_gre_ipv4_tcp':0,
'ipv4_ptp':0,
'ctrl_pkts':0,
}

ipdststart = { 0: "192.18.0.1",
	       1: "172.25.14.1",
	       2: "172.25.15.1",
	       3: "172.25.16.1",
	       4: "172.25.17.1",
	       5: "172.25.18.1",
	       6: "172.25.19.1",
	       7: "172.25.20.1",
	       8: "172.25.21.1",
	       9: "172.25.22.1",
	       10: "172.25.23.1",
	       11: "172.25.24.1", }
dmac = dutmac#"22:E7:F5:31:C0:C0"#"3E:5F:32:15:AD:23"#"8E:94:98:7D:57:E8"#"3A:58:C0:65:1C:79"#"12:4e:31:15:b0:1b"
tundip = "1.1.1.2"
tundip6 = "::1.1.1.2"
dport = 9
tcp_flags = "PAFC"

# List of control pkts
ctrl_pkt_list = []
ctrl_pkt_list += Ether(dst=dmac)/ARP()
ctrl_pkt_list += Ether(dst=dmac)/IP()/ICMP()
ctrl_pkt_list += Ether(dst=dmac)/IP()/ESP()
ctrl_pkt_list += Ether(dst=dmac)/IPv6()/ESP()
#ctrl_pkt_list += Ether(dst=dmac, type=0x8035)/Raw("ABCDEF")
ctrl_pkt_list += Ether(dst=dmac)/IP()/GRE()
#ctrl_pkt_list += Ether(dst=dmac, type=0x8847)/Raw("ABCDEF")

a = [None] * 1
a6 = [None] * 1
a[0] = ipaddress.ip_address(ipdststart[0])
a6[0] = ipaddress.ip_address("::" + ipdststart[0])

fo = None
sent_file = None
expect_file = None
recv_file = None
buf = ""
array_name_str = "static uint8_t *test_pkt[] = {\n"
array_len_str = "static uint16_t test_pkt_len[] = {\n"
dump_file = "/home/build/dpdk/96xx/dpdk/app/test-pmd/pkts.h"
sent_file_name = "./sent.txt"
expect_file_name = "./expect.txt"
recv_file_name = "./recv.txt"
total_pkts_count = 0
good_pkts_count = 0

def printf(format, *args):
	sys.stdout.write(format % args)

def fprintf(file, format, *args):
	file.write(bytes(format % args, 'UTF-8'))

def clear_bad_checksum(pkt, good):
	if good != 1:
		return
	i = 0
	j = 0
	while pkt.firstlayer()[i].name != pkt.lastlayer().name:
		try:
			del pkt.firstlayer()[i].chksum
		except:
			j = j + 1
		i = i + 1
	return

def remove_padding(pkt):
	if pkt.haslayer(Padding) == 0:
		return

	old_len = len(pkt)
	pad_len = len(pkt[Padding])
	new_len = old_len - pad_len
	i = 0
	while pkt.firstlayer()[i].name != pkt.lastlayer().name:
		i = i + 1
	if i < 1:
		printf("Error: Padding with one layer!!!\n")
		return
	pkt.firstlayer()[i - 1].remove_payload()

	if pkt.haslayer(Padding) == 1:
		printf("Error: Padding remove failed!!!\n")

	if len(pkt) != new_len:
		printf("Error: Unexpected truncation before %u, pad %u, after %u, i %u\n" % (old_len, pad_len, len(pkt), i))

	return

def pkt_name(pkt):
	i = 0
	global buf
	global count
	buf = ""
	while pkt.firstlayer()[i].name != pkt.lastlayer().name:
		if i != 0:
			buf += "_"
		tmp = pkt.firstlayer()[i].name
		if tmp == "802.1Q":
			tmp = "802_1Q"
		buf += "%s" % tmp
		i = i + 1
	buf += "_%u" % count
	return buf

def pkt_data_dump(pkt):
	global array_name_str
	global array_len_str
	global fo
	if not fo:
		fo = open(dump_file, "wb+")
	fprintf(fo, "\n")
	name = pkt_name(pkt)
	fprintf(fo, "static uint8_t %s[] = {" % name)
	array_name_str += "\t%s,\n" % name
	array_len_str += "\t%u, //%s\n" % (pkt.__len__(), name)
	i = 0
	for i in range(pkt.__len__()):
		if (i % 8 == 0):
			fprintf(fo, "\n\t")
		fprintf(fo, "0x%0.2x, " % (pkt.__bytes__()[i]))
	fprintf(fo, "\n};\n")

# Creates a string exactly of given size
lineterm = '#' #'\n' could be used
def pkt_data_str(str1, str2, size):
	string = str1 + str2
	end = string + '\n'
	string = '\n' + string
	itr = 1
	last = 0;
	while len(string) < (size - 2 * len(end)) :
		string = string + '#' + str(itr)
		itr = itr + 1
		if len(string) - last > 70 :
			string = string + lineterm
			last = len(string)
	string = string + '#' + end
	while len(string) < size:
	 	if len(string) + 1 == size:
	 		string = string + '\n'
	 	else:
	 		string = string + '#'
	return string

def grep_pkt(pkt_list, payload):
	for i in pkt_list:
		load = i.lastlayer().load
		if load == payload:
			return i
	for i in pkt_list:
		if i.getlayer(3).name == 'VXLAN':
			t = Ether(i.getlayer(4).load)
			load = t.lastlayer().load
		else:
			load = i.lastlayer().load
		if load == payload:
			return i
	return None

def sniff_and_check_sanity(sent_list, recv_list):
	global sent_file
	global expect_file
	global recv_file
	global good_pkts_count
	if not sent_file:
		sent_file = open(sent_file_name, "wb+")
	if not expect_file:
		expect_file = open(expect_file_name, "wb+")
	if not recv_file:
		recv_file = open(recv_file_name, "wb+")

	if len(sent_list) != len(recv_list):
		print("sent %u != recv %u\n" % (len(sent_list), len(recv_list)))
		for i in sent_list:
			sent_file.write(bytes(i.show2(dump=True), 'UTF-8'))
		for i in recv_list:
			recv_file.write(bytes(i.show2(dump=True), 'UTF-8'))
		return
	itr = 0
	for pkt in sent_list:
		if ctrl_pkts == 0:
			# Grep for packet by comparing last layer payload
			recv_pkt = grep_pkt(recv_list, pkt.lastlayer().load)
			if recv_pkt == None:
				printf("Below mentioned pkt is missing? payload corruption?\n")
				pkt.show2()
				exit()
		else:
			recv_pkt = recv_list[itr]
			itr = itr + 1

		# Compare only after Ethernet header
		pkt = pkt[Ether].payload
		recv_pkt = recv_pkt[Ether].payload

		fprintf(sent_file, "\n%s\n" % pkt_name(pkt))
		sent_buf = pkt.show2(dump=True)
		sent_file.write(bytes(sent_buf, 'UTF-8'))

		clear_bad_checksum(pkt, 1)
		fprintf(expect_file, "\n%s\n" % pkt_name(pkt))
		expect_buf = pkt.show2(dump=True)
		expect_file.write(bytes(expect_buf, 'UTF-8'))

		fprintf(recv_file, "\n%s\n" % pkt_name(recv_pkt))
		recv_buf = recv_pkt.show2(dump=True)
		recv_file.write(bytes(recv_buf, 'UTF-8'))
		diff = difflib.unified_diff(expect_buf.splitlines(1), recv_buf.splitlines(1), fromfile='expected', tofile='received')
		good=1
		for line in diff:
			# Print diffing packet name
			if good == 1:
				printf("\n\n%s\n" % pkt_name(pkt))
			printf("%s" % str(line))
			good=0
		good_pkts_count = good_pkts_count + good
	return

# Helper functions
def tun_ip():
	return Ether(dst=dmac)/IP(dst=tundip,chksum=0xdead)

def tun_ip6():
	return Ether(dst=dmac)/IPv6(dst=tundip6)

def tun_ip_udp(s_port, d_port):
	return Ether(dst=dmac)/IP(dst=tundip,chksum=0xdead)/UDP(dport=int(d_port), sport=int(s_port), chksum=0xdead)

def tun_ip6_udp(s_port, d_port):
	return Ether(dst=dmac)/IPv6(dst=tundip6)/UDP(dport=int(d_port), sport=int(s_port), chksum=0xdead)

def in_ip_tcp(d_ip, s_port, d_port):
	if inner_checksum_dontcare == 0:
		return IP(dst=d_ip,chksum=0xbeef, ttl=(1,1))/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags,chksum=0xdead)
	else:
		return IP(dst=d_ip, ttl=(1,1))/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags)

def in_ip6_tcp(d_ip6, s_port, d_port):
	if inner_checksum_dontcare == 0:
		return IPv6(dst=d_ip6)/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags,chksum=0xdead)
	else:
		return IPv6(dst=d_ip6)/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags)

def geneve(vni_id, proto_id):
	return scapy.contrib.geneve.GENEVE(vni=int(vni_id), proto=int(proto_id))

count = 0
flow_types = 0

# Process command line args
not_def=0
for x in sys.argv:
	if x == sys.argv[0]:
		continue
	# Overriding default bool options when args are given
	if not_def == 0:
		not_def=1
		printf("Overriding default bool opts\n")
		for key in opt_dict.keys():
			opt_dict[key]=0

	reObj = re.compile(x)
	for key in opt_dict.keys():
		if(reObj.match(key)):
			opt_dict[key]=1

if recv_sanity == 1:
	printf("####Testing received pkts sanity with DUT mac %s####\n" % str(dutmac))

str1 = "bad"
if good_checksum != 0:
	str1 = "good"
printf("#####Sending below protocol packets with %s cksum on %s####\n" % (str1, ethdev_name))

# Convert opt dict to variables
for opt in opt_dict:
	exec("%s = %d" % (opt,opt_dict[opt]))
	if opt == "good_checksum":
		continue
	if opt == "ctrl_pkts":
		if int(opt_dict[opt]) != 0:
			flow_types += len(ctrl_pkt_list)
			continue
	if int(opt_dict[opt]) != 0:
		printf("\t%s\n" % opt)
		flow_types += 1

test_pkts_count = flow_types * burst_size * pkt_bursts

# Disable gro
printf("Setting GRO off on %s\n" % ethdev_name)
cmd = "ethtool -K %s gro off" % ethdev_name
os.system(str(cmd))
cmd = "ethtool -k %s |grep gro" % ethdev_name
os.system(str(cmd))
# Enable promisc
printf("Enabling promisc on %s\n" % ethdev_name)
cmd = "ifconfig %s promisc" % ethdev_name
os.system(str(cmd))
# Enable interface
cmd = "ifconfig %s up" % ethdev_name
os.system(str(cmd))
# Disable ip6 da and ra
cmd = "echo 0 >/proc/sys/net/ipv6/conf/%s/dad_transmits" % ethdev_name
os.system(str(cmd))
cmd = "echo 0 >/proc/sys/net/ipv6/conf/%s/router_solicitations" % ethdev_name
os.system(str(cmd))

def signal_handler(sig, frame):
	print('You pressed Ctrl+C!. Killing tcpdump!!!')
	os.kill(full.pid, signal.SIGKILL)
	sys.exit(0)

# Start a full capture if requested
if capture_rx != 0:
	full = subprocess.Popen(['tcpdump', '-U', '--immediate-mode', '-i', str(ethdev_name),
				'-w', 'full.pcap', '-s 0'], stdout=subprocess.PIPE,
				stderr=DEVNULL)
	time.sleep(4)
	signal.signal(signal.SIGINT, signal_handler)

while count < pkt_bursts:
	dip = str(a[0])
	dip6 = str(a6[0])
	a[0] = a[0] + (1)
	a6[0] = a6[0] + (1 << 16)
	name = str(ethdev_name)
	pkt_list = []
	set_string = 'S#%u#' % count

	# Send one burst of all protocols of in single flow
	for j in range(burst_size):
		#print(name)
		#print(i)
		#print(ipdst)
		#print(a)
		#prepare strings for packet data
		pkttype=1
		#Standard set of ctrl packets
		if ctrl_pkts != 0:
			for pkt in ctrl_pkt_list:
				pkt_list += pkt
				pkttype += 1
		#IPv4 PTP
		if ipv4_ptp != 0:
			pkt = Ether(dst=dmac,type=0x88f7)/"\x00\x02"
			string = pkt_data_str(set_string, 'IPv4PTP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPv4 TCP
		if ipv4_tcp != 0:
			pkt = Ether(dst=dmac)/IP(dst=dip, chksum=0xbeef, ttl=(1,1))/TCP(dport=int(dport), sport=pkttype, flags=tcp_flags,chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4 UDP
		if ipv4_udp != 0:
			pkt = Ether(dst=dmac)/IP(dst=dip,chksum=0xbeef, ttl=(1,1))/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv4UDP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4 SCTP
		if ipv4_sctp != 0:
			pkt = Ether(dst=dmac)/IP(dst=dip,chksum=0xbeef, ttl=(1,1))/SCTP(dport=int(dport), sport=pkttype, chksum=0)
			string = pkt_data_str(set_string, 'IPv4SCTP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPv6 TCP
		if ipv6_tcp != 0:
			pkt = Ether(dst=dmac)/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6 UDP
		if ipv6_udp != 0:
			pkt = Ether(dst=dmac)/IPv6(dst=dip6)/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv6UDP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6 SCTP
		if ipv6_sctp != 0:
			pkt = Ether(dst=dmac)/IPv6()/SCTP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv6SCTP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4/GRE/IPV4/TCP
		if ipv4_gre_ipv4_tcp != 0:
			pkt = tun_ip()/GRE(proto=0x0800)/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv4GREIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6/GRE/IPV4/TCP
		if ipv6_gre_ipv4_tcp != 0:
			pkt = tun_ip6()/GRE(proto=0x0800)/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv6GREIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1


		#IPV4/GRE/IPV6/TCP
		if ipv4_gre_ipv6_tcp != 0:
			pkt = tun_ip()/GRE(proto=0x86DD)/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv4GREIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6/GRE/IPV6/TCP
		if ipv6_gre_ipv6_tcp != 0:
			pkt = tun_ip6()/GRE(proto=0x86DD)/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv6GREIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4/VXLAN/IPV4/TCP
		if ipv4_vxlan_ipv4_tcp != 0:
			pkt = tun_ip_udp(pkttype, 4789)/VXLAN(vni=0x3355, flags=0x8)/Ether()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv4VXLANIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6/VXLAN/IPV4/TCP
		if ipv6_vxlan_ipv4_tcp != 0:
			pkt = tun_ip6_udp(pkttype, 4789)/VXLAN(vni=0x3355, flags=0x8)/Ether()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv6VXLANIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1
		#IPV4/VXLAN/IPV6/TCP
		if ipv4_vxlan_ipv6_tcp != 0:
			pkt = tun_ip_udp(pkttype, 4789)/VXLAN(vni=0x3355, flags=0x8)/Ether()/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv4VXLANIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6/VXLAN/IPV6/TCP
		if ipv6_vxlan_ipv6_tcp != 0:
			pkt = tun_ip6_udp(pkttype, 4789)/VXLAN(vni=0x3355, flags=0x8)/Ether()/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv6VXLANIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4/GENEVE/IPV4/TCP
		if ipv4_geneve_ipv4_tcp != 0:
			pkt = tun_ip_udp(pkttype, 6081)/geneve(0x3355, 0x6558)/Ether()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv4GENEVEIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6/GENEVE/IPV4/TCP
		if ipv6_geneve_ipv4_tcp != 0:
			pkt = tun_ip6_udp(pkttype, 6081)/geneve(0x3355, 0x6558)/Ether()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv6GENEVEIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1
		#IPV4/GENEVE/IPV6/TCP
		if ipv4_geneve_ipv6_tcp != 0:
			pkt = tun_ip_udp(pkttype, 6081)/geneve(0x3355, 0x6558)/Ether()/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv4GENEVEIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6/GENEVE/IPV6/TCP
		if ipv6_geneve_ipv6_tcp != 0:
			pkt = tun_ip6_udp(pkttype, 6081)/geneve(0x3355, 0x6558)/Ether()/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'IPv6GENEVEIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1
		#Dot1Q IPv4 TCP
		if dot1q_ipv4_tcp != 0:
			pkt = Ether(dst=dmac)/Dot1Q()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1QIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1Q IPv6 TCP
		if dot1q_ipv6_tcp != 0:
			pkt = Ether(dst=dmac)/Dot1Q()/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1QIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1Q/IPV4/GRE/IPV4/TCP
		if dot1q_ipv4_gre_ipv4_tcp != 0:
			pkt = Ether(dst=dmac)/Dot1Q()/IP(chksum=0xdead)/GRE(proto=0x0800)/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1QIPv4GREIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1AD Dot1Q IPv4 TCP
		if dot1ad_dot1q_ipv4_tcp != 0:
			pkt = Ether(dst=dmac)/Dot1AD()/Dot1Q()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1ADDot1QIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1AD Dot1Q IPv6 TCP
		if dot1ad_dot1q_ipv6_tcp != 0:
			pkt = Ether(dst=dmac)/Dot1AD()/Dot1Q()/in_ip6_tcp(dip6, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1ADDot1QIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1AD/Dot1Q/IPV4/GRE/IPV4/TCP
		if dot1ad_dot1q_ipv4_gre_ipv4_tcp != 0:
			pkt = Ether(dst=dmac)/Dot1AD()/Dot1Q()/IP(chksum=0xdead)/GRE(proto=0x0800)/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1ADDot1QIPv4GREIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		# Dump packets to pkts.h
		if dump != 0:
			for pkt in pkt_list:
				pkt_data_dump(pkt)

	for pkt in pkt_list:
		clear_bad_checksum(pkt, good_checksum)
	# Send burst
	sendp(pkt_list, count=1, iface=str(name), verbose=0, return_packets=0)

	#printf("Sent pkt of size %u\n" % size)
	#time.sleep(4)
	count = count + 1
	total_pkts_count = total_pkts_count + len(pkt_list)
	printf("\r")
	printf("Sent packets %u/%u" % (total_pkts_count, test_pkts_count))
	# Reset ip series when flows reached
	if count % flows == 0:
		a[0] = ipaddress.ip_address(ipdststart[0])
		a6[0] = ipaddress.ip_address("::" + ipdststart[0])
	size = size + sizeinc
	if size > maxsize:
	  	size = minsize

printf("\n")
if dump != 0:
	fprintf(fo, "\n%s\n};" % array_name_str)
	fprintf(fo, "\n%s\n};" % array_len_str)
	fprintf(fo, "\n\n#define TEST_PKT_COUNT (sizeof(test_pkt)/sizeof(uint8_t *))")
	fprintf(fo, "\n#define TEST_PKTS")

def dump_pkt_load(pkt, fd):
	if pkt.lastlayer() != None:
		try:
			if pkt.getlayer(3).name == 'VXLAN':
				t = Ether(pkt.getlayer(4).load)
				load = t.lastlayer().load
			else:
				load = pkt.lastlayer().load
			fd.write(load)
		except:
			j = 0
if capture_rx != 0:
	name = input("Hit any key to stop full capture and quit: ")
	os.kill(full.pid, signal.SIGINT)
	full.wait()

# Split sent and recv
	if os.path.isfile('full-sent.pcap'):
		os.remove('full-sent.pcap')
	if os.path.isfile('full-recv.pcap'):
		os.remove('full-recv.pcap')

	sent_filter = "ether dst %s" % dutmac.lower()
	recv_filter = "not ether dst %s" % dutmac.lower()
	s = subprocess.Popen(['tcpdump', '-r', 'full.pcap',
				'-w', 'full-sent.pcap', sent_filter], stdout=subprocess.PIPE,
				stderr=DEVNULL)

	r = subprocess.Popen(['tcpdump', '-r', 'full.pcap',
				'-w', 'full-recv.pcap', recv_filter], stdout=subprocess.PIPE,
				stderr=DEVNULL)
	s.wait();
	r.wait();

	if name != '':
		os.rename('full.pcap', '%s-full.pcap' % name)
		os.rename('full-sent.pcap', '%s-full-sent.pcap' % name)
		os.rename('full-recv.pcap', '%s-full-recv.pcap' % name)
		printf("Please check complete capture in %s-[full|full-sent|full-recv].pcap\n" % name)
	else:
		printf("Please check complete capture in [full|full-sent|full-recv].pcap\n")

	printf("Extracting full-sent and full-recv payload\n")

	fds = open('full-sent.payload', "wb+")
	fdr = open('full-recv.payload', "wb+")

	sent_list = sniff(offline="full-sent.pcap")
	for pkt in sent_list:
		dump_pkt_load(pkt, fds)

	recv_list = sniff(offline="full-recv.pcap")
	if len(recv_list) != 0:
		min_pad = 0
		max_pad = 0
		new_recv_list = []
		i = 0
		for pkt in recv_list:
			if pkt.haslayer(Padding) == 1:
				if min_pad > len(pkt[Padding]):
					min_pad = len(pkt[Padding])

				if max_pad < len(pkt[Padding]):
					max_pad = len(pkt[Padding])

				i = i + 1
				remove_padding(pkt)

			new_recv_list += pkt
		recv_list = new_recv_list
		if min_pad != 0 or max_pad != 0 :
			printf("Removed padding in range of %uB..%uB from %u/%u packets!!!\n" % (min_pad, max_pad, i, len(recv_list)))

	for pkt in recv_list:
		dump_pkt_load(pkt, fdr)

	if recv_sanity != 0:
		sniff_and_check_sanity(sent_list, recv_list)
		printf("\rResult as expected for %d/%d pkts\n" % (good_pkts_count, total_pkts_count))
		if total_pkts_count != good_pkts_count:
			printf("Please check sent.txt, expect.txt, recv.txt for errors\n")
