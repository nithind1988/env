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
import argparse
from subprocess import DEVNULL
from threading import Timer
ethdev_name="asimnic0"
dutmac = "3e:23:24:7c:6a:b5"
testermac = "2E:8F:CC:AD:7A:9F"
capture_rx=1
recv_sanity=1
sizeinc = 13
minsize = 64#7000#7000#128#7000
maxsize = 1400#1400#8512#1400#9000
size = minsize
dump = 0
burst_size = 1
pkt_bursts, flows = (1, 1)
good_checksum=1
inner_checksum_dontcare=0
ipsec_sas = 16
inb_ipsec = 0
outb_ipsec = 0

#default bool opts
opt_dict = {
'ipv4_tcp':1,
'ipv4_udp':0,
'ipv4_sctp':0,
'ipv6_tcp':0,
'ipv6_udp':0,
'ipv6_sctp':0,
'ipv4_gre_ipv4_tcp':0,
'ipv6_gre_ipv4_tcp':0,
'ipv4_gre_ipv6_tcp':0,
'ipv6_gre_ipv6_tcp':0,
'ipv4_vxlan_ipv4_tcp':0,
'ipv6_vxlan_ipv4_tcp':0,
'ipv4_vxlan_ipv6_tcp':0,
'ipv6_vxlan_ipv6_tcp':0,
'ipv4_geneve_ipv4_tcp':0,
'ipv6_geneve_ipv4_tcp':0,
'ipv4_geneve_ipv6_tcp':0,
'ipv6_geneve_ipv6_tcp':0,
'dot1q_ipv4_tcp':0,
'dot1q_ipv6_tcp':0,
'dot1q_ipv4_gre_ipv4_tcp':0,
'dot1ad_dot1q_ipv4_tcp':0,
'dot1ad_dot1q_ipv6_tcp':0,
'dot1ad_dot1q_ipv4_gre_ipv4_tcp':0,
'ipv4_ptp':0,
'ctrl_pkts':0,
}

ipdststart = { 0: "192.18.0.0",
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
sip = "193.18.0.1"
sip6 = "::193.18.0.1"
tundip = "1.1.1.1"
tundip6 = "::1.1.1.1"
tunsip = "2.1.1.1"
tunsip6 = "::2.1.1.1"
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
sessions = [None] * 256

buf = ""
array_name_str = "static uint8_t *test_pkt[] = {\n"
array_len_str = "static uint16_t test_pkt_len[] = {\n"
dump_file = "/home/build/dpdk/96xx/dpdk-cavium/app/test-pmd/pkts.h"
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
	return Ether(dst=dmac)/IP(dst=tundip,src=tunsip,chksum=0xdead)

def tun_ip6():
	return Ether(dst=dmac)/IPv6(dst=tundip6,src=tunsip6)

def tun_ip_udp(s_port, d_port):
	return Ether(dst=dmac)/IP(dst=tundip,src=tunsip, chksum=0xdead)/UDP(dport=int(d_port), sport=int(s_port), chksum=0xdead)

def tun_ip6_udp(s_port, d_port):
	return Ether(dst=dmac)/IPv6(dst=tundip6, src=tunsip6)/UDP(dport=int(d_port), sport=int(s_port), chksum=0xdead)

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
parser = argparse.ArgumentParser()
parser.add_argument("--proto", type=str, help="Regex of protocol packets to send")
parser.add_argument("--inb-ipsec", help="Test inbound ipsec",
		    action="store_true")
parser.add_argument("--outb-ipsec", help="Test outbound ipsec",
		    action="store_true")
parser.add_argument("--pkt-bursts", type=int, help="Number of pkt bursts to send")
parser.add_argument("--flows", type=int, help="Number of flows to send")
parser.add_argument("--burst-size", type=int, help="Burst size of pkt burst")
parser.add_argument("--bad-chksum", help="Generate plain pkts with bad checksum",
		    action="store_true")
parser.add_argument("-i", "--interface", type=str, help="Interface to DUT",
		    required=False, default=str(ethdev_name))
parser.add_argument("--minsize", type=int, help="Min pkt size",
		    required=False, default=minsize)
parser.add_argument("--maxsize", type=int, help="Max pkt size",
		    required=False, default=maxsize)
parser.add_argument("--ipsec-sas", type=int, help="IPSec SA's to create",
		    required=False, default=ipsec_sas)

opt_str = ""
args = parser.parse_args()
if args.inb_ipsec and args.outb_ipsec:
	printf("Invalid arguments, both inbound and outbound cannot be enabled")
	sys.exit(-1)
if args.inb_ipsec:
	inb_ipsec = 1
	opt_str = opt_str + "inb_ipsec=1 "
if args.outb_ipsec:
	outb_ipsec = 1
	opt_str = opt_str + "outb_ipsec=1 "
if args.pkt_bursts:
	pkt_bursts = args.pkt_bursts
if args.flows:
	flows = args.flows
if args.burst_size:
	burst_size = args.burst_size
if args.bad_chksum:
	good_checksum = 0
	opt_str = opt_str + "bad_chksum=1 "
if args.interface:
	ethdev_name = args.interface
if args.minsize:
	minsize = args.minsize
if args.maxsize:
	maxsize = args.maxsize

if args.proto:
	for key in opt_dict.keys():
		opt_dict[key]=0

	x = str(args.proto)
	# Overriding default bool options when args are given
	printf("Overriding default bool opts\n")

	reObj = re.compile(x)
	for key in opt_dict.keys():
		if(reObj.match(key)):
			opt_dict[key]=1

if inb_ipsec or outb_ipsec:
	opt_str = opt_str + "ipsec_sas=%u " % ipsec_sas

opt_str = opt_str + "pkt_bursts=%u flows=%u burst_size=%u " % (pkt_bursts, flows, burst_size)
opt_str = opt_str + "minsize=%u maxsize=%u" % (minsize, maxsize)
printf("DUTMAC     : %s\n" % str(dutmac))
printf("Interface  : %s\n" % ethdev_name)
printf("Options    : %s\n\n" % opt_str)
printf("Protocols for plain pkts: ")

# Convert opt dict to variables
for opt in opt_dict:
	exec("%s = %d" % (opt,opt_dict[opt]))
	if opt == "ctrl_pkts":
		if int(opt_dict[opt]) != 0:
			flow_types += len(ctrl_pkt_list)
			continue
	if int(opt_dict[opt]) != 0:
		printf("%s " % opt)
		flow_types += 1

printf("\n##############################################################\n\n")

test_pkts_count = flow_types * burst_size * pkt_bursts

# Disable gro
#printf("Setting GRO off on %s\n" % ethdev_name)
cmd = "ethtool -K %s gro off" % ethdev_name
os.system(str(cmd))
cmd = "ethtool -k %s |grep gro" % ethdev_name
os.system(str(cmd))
# Enable promisc
#printf("Enabling promisc on %s\n" % ethdev_name)
cmd = "ifconfig %s promisc" % ethdev_name
os.system(str(cmd))
# Enable interface
cmd = "ifconfig %s up" % ethdev_name
os.system(str(cmd))
# Disable ip6 DA and RA
proc_path = "/proc/sys/net/ipv6/conf/%s/dad_transmits" % ethdev_name
if os.path.exists(str(proc_path)):
	cmd = "echo 0 >/proc/sys/net/ipv6/conf/%s/dad_transmits" % ethdev_name
	os.system(str(cmd))
proc_path = "/proc/sys/net/ipv6/conf/%s/router_solicitations" % ethdev_name
if os.path.exists(str(proc_path)):
	cmd = "echo 0 >/proc/sys/net/ipv6/conf/%s/router_solicitations" % ethdev_name
	os.system(str(cmd))

if os.path.exists("tr_files") == 0:
	os.mkdir('tr_files')
os.chdir('./tr_files')

def signal_handler(sig, frame):
	print('You pressed Ctrl+C!. Killing tcpdump!!!')
	os.kill(full.pid, signal.SIGKILL)
	sys.exit(0)

# Start a full capture if requested
if capture_rx != 0:
	full = subprocess.Popen(['tcpdump', '-U', '--immediate-mode', '-i', str(ethdev_name),
				'-w', 'full.pcap', '-s 0'], stdout=subprocess.PIPE,
				stderr=DEVNULL)
	signal.signal(signal.SIGINT, signal_handler)
	time.sleep(4)

if inb_ipsec == 0 and outb_ipsec == 0:
	ipsec_sas = 0

ipsec_secgw_fname = 'gw.conf'
if inb_ipsec == 1:
	ipsec_secgw_fname = 'gw_i.conf'
if ipsec_sas != 0:
	if os.path.isfile(str(ipsec_secgw_fname)):
		os.remove(str(ipsec_secgw_fname))
	gw_fd = open(str(ipsec_secgw_fname), "wb+")

spi_base = 0x13
for i in range(ipsec_sas):
	spi = int(spi_base) + i
	sa = SecurityAssociation(ESP, spi=int(spi), crypt_algo='AES-GCM',
				 crypt_key=b'sixteenbytes keydpdk',
				 tunnel_header=IP(src=tunsip, dst=tundip))
	sessions[i] = sa
	# Write out DPDK conf for the same
	cipher_key = ':'.join(hex(x)[2:] for x in sa.crypt_key)
	cipher_key = cipher_key + ':' + ':'.join(hex(x)[2:] for x in sa.crypt_salt)
	offloadopt = 'type inline-protocol-offload port_id 0'

	if inb_ipsec != 0:
		fprintf(gw_fd, 'sp ipv4 in esp protect %u pri 1 dst 192.18.%u.0/24 sport 0:65535 dport 0:65535\n' % (spi, i))
		fprintf(gw_fd, 'sa in %u aead_algo aes-128-gcm aead_key %s ' % (spi, cipher_key))
		fprintf(gw_fd, 'mode ipv4-tunnel src %s dst %s %s\n' % (tunsip, tundip, offloadopt))
	else:
		fprintf(gw_fd, 'sp ipv4 out esp protect %u pri 1 dst 192.18.%u.0/24 sport 0:65535 dport 0:65535\n' % (spi, i))
		fprintf(gw_fd, 'sa out %u aead_algo aes-128-gcm aead_key %s ' % (spi, cipher_key))
		fprintf(gw_fd, 'mode ipv4-tunnel src %s dst %s %s\n' % (tunsip, tundip, offloadopt))

	if i == ipsec_sas - 1:
		fprintf(gw_fd, 'neigh port 0 11:22:33:44:55:66\n')
		fprintf(gw_fd, 'rt ipv4 dst 192.18.0.0/16 port 0\n')
		fprintf(gw_fd, 'rt ipv4 dst 2.1.0.0/16 port 0\n')

	# Dummy SA out to trigger LF setup
#fprintf(fd, 'sa out 109999 aead_algo aes-128-gcm aead_key %s ' % cipher_key)
#	fprintf(fd, 'mode ipv4-tunnel src %s dst %s %s\n' % (tunsip, tundip, offloadopt))

if ipsec_sas != 0:
	gw_fd.close()
	c = input("IPSec-GW conf stored at tr_files/%s, hit any key to continue:" % ipsec_secgw_fname)

sa = sessions[0]
next_sa = sa
size = minsize

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
			pkt = Ether(dst=dmac)/IP(dst=dip, src=sip, chksum=0xbeef, ttl=(1,1))/TCP(dport=int(dport), sport=pkttype, flags=tcp_flags,chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4 UDP
		if ipv4_udp != 0:
			pkt = Ether(dst=dmac)/IP(dst=dip,src=sip, chksum=0xbeef, ttl=(1,1))/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv4UDP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4 SCTP
		if ipv4_sctp != 0:
			pkt = Ether(dst=dmac)/IP(dst=dip,src=sip,chksum=0xbeef, ttl=(1,1))/SCTP(dport=int(dport), sport=pkttype, chksum=0)
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
			pkt = Ether(dst=dmac)/IPv6(dst=dip6, src=sip6)/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
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

	new_pkt_list = []
	for pkt in pkt_list:
		if inb_ipsec != 0:
			sa = next_sa

			# Checksum is always good for ipsec
			clear_bad_checksum(pkt, 1)
			l = pkt[Ether].payload
			if pkt.firstlayer()[1].name == '802.1Q':
				l = pkt[Dot1Q].payload
				new_pkt_list += Ether(dst=dmac)/Dot1Q()/sa.encrypt(l)
			else:
				new_pkt_list += Ether(dst=dmac)/sa.encrypt(l)
		else:
			clear_bad_checksum(pkt, good_checksum)
			new_pkt_list += pkt
	# Send burst
	sendp(new_pkt_list, count=1, iface=str(name), verbose=0, return_packets=0)

	#printf("Sent pkt of size %u\n" % size)
	#time.sleep(4)
	count = count + 1

	# Move to next sa 
	if  ipsec_sas != 0:
		sa_i = count % ipsec_sas
		next_sa = sessions[sa_i]
		a[0] = ipaddress.ip_address(ipdststart[0])
		a6[0] = ipaddress.ip_address("::" + ipdststart[0])
		a[0] = a[0] + (sa_i << 8)
		a6[0] = a6[0] + (sa_i << 24)

	total_pkts_count = total_pkts_count + len(pkt_list)
	printf("\r")
	printf("Sent packets %u/%u" % (total_pkts_count, test_pkts_count))
	# Reset ip series when flows reached
	if count % flows == 0:
		a[0] = ipaddress.ip_address(ipdststart[0])
		a6[0] = ipaddress.ip_address("::" + ipdststart[0])
		next_sa = sessions[0]
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
		printf("Please check complete capture in tr_files/%s-[full|full-sent|full-recv].pcap\n" % name)
	else:
		printf("Please check complete capture in tr_files/[full|full-sent|full-recv].pcap\n")

	printf("Extracting full-sent and full-recv payload\n")

	fds = open('full-sent.payload', "wb+")
	fdr = open('full-recv.payload', "wb+")

	sent_list = sniff(offline="full-sent.pcap")

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

	if inb_ipsec != 0:
		os.rename('full-sent.pcap', 'full-sent-cipher.pcap')
		cipher_sent_list = sent_list
		sent_list = []
		for pkt in cipher_sent_list:
			spi = pkt[ESP].spi
			idx = int(spi) - int(spi_base)
			sa = sessions[idx]
			sent_list += Ether(dst=dmac)/sa.decrypt(pkt[Ether].payload)
		# Write plain pkts out
		wrpcap('full-sent.pcap', sent_list)

	if outb_ipsec != 0:
		os.rename('full-recv.pcap', 'full-recv-cipher.pcap')
		cipher_recv_list = recv_list
		recv_list = []
		for pkt in cipher_recv_list:
			spi = pkt[ESP].spi
			idx = int(spi) - int(spi_base)
			sa = sessions[idx]
			recv_list += Ether(dst=dmac)/sa.decrypt(pkt[Ether].payload)
		# Write plain pkts out
		wrpcap('full-recv.pcap', recv_list)

	for pkt in sent_list:
		dump_pkt_load(pkt, fds)

	for pkt in recv_list:
		dump_pkt_load(pkt, fdr)

	if recv_sanity != 0:
		sniff_and_check_sanity(sent_list, recv_list)
		printf("\rResult as expected for %d/%d pkts\n" % (good_pkts_count, total_pkts_count))
		if total_pkts_count != good_pkts_count:
			printf("Please check sent.txt, expect.txt, recv.txt for errors\n")
