#!/usr/bin/env python3

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
capture_rx=1
recv_sanity=1
sizeinc = 13
minsize = 64#7000#7000#128#7000
maxsize = 1400#1400#8512#1400#9000
size = minsize
dump = 1
burst_size = 1
pkt_bursts, flows = (1, 1)
good_checksum=1
inner_checksum_dontcare=0
ipsec_sas = 16
outb_accept_plain = 0
inb_ipsec = 0
outb_ipsec = 0
transport = 0
ipsec_v6_tunnel = 0
esn_en = 0
ipv4_proto = 1
ipv6_proto = 0
fragment_size = 0

#default bool opts
opt_dict = {
'ipv4_tcp':1,
'ipv4_udp':0,
'ipv4_sctp':0,
'ipv6_tcp':0,
'ipv6_udp':0,
'ipv6_ext_udp':0,
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

ipdststart = "198.18.0.0"
smac = "02:00:00:00:01:00"
dmac = "02:00:00:00:00:00"
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
#ctrl_pkt_list += Ether(src=smac,dst=dmac)/ARP()
#ctrl_pkt_list += Ether(src=smac,dst=dmac)/IP()/ICMP()
#ctrl_pkt_list += Ether(src=smac,dst=dmac)/IP()/ESP()
#ctrl_pkt_list += Ether(src=smac,dst=dmac)/IPv6()/ESP()
#ctrl_pkt_list += Ether(src=smac,dst=dmac, type=0x8035)/Raw("ABCDEF")
ctrl_pkt_list += Ether(src=smac,dst=dmac)/IP()/GRE()
#ctrl_pkt_list += Ether(src=smac,dst=dmac, type=0x8847)/Raw("ABCDEF")

fo = None
sent_file = None
expect_file = None
recv_file = None
sessions = [None] * 256

buf = ""
array_name_str = "static uint8_t *test_pkt[] = {\n"
array_len_str = "static uint16_t test_pkt_len[] = {\n"
dump_file = "./pkts.h"
sent_file_name = "./sent.txt"
expect_file_name = "./expect.txt"
recv_file_name = "./recv.txt"
total_pkts_count = 0
good_pkts_count = 0
outb_plain_pkts = 0

def printf(format, *args):
	sys.stdout.write(format % args)

def fprintf(file, format, *args):
	file.write(bytes(format % args, 'UTF-8'))

def checksum_override(pkt, good):
	i = 0
	j = 0
	while pkt.firstlayer()[i].name != pkt.lastlayer().name:
		try:
			if good == 1:
				del pkt.firstlayer()[i].chksum
			else:
				pkt.firstlayer()[i].chksum = 0xdead
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
	tmp = pkt.lastlayer().name
	buf += "_%s" % tmp
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
	# Dump for Ixia
	if dump == 2:
		fprintf(fo, "###%s" % name)
		i = 0
		for i in range(pkt.__len__()):
			if (i % 8 == 0):
				fprintf(fo, "\n")
			fprintf(fo, "%02x " % (pkt.__bytes__()[i]))
	else:
		fprintf(fo, "static uint8_t %s[] = {\n\t" % name)
		array_name_str += "\t%s,\n" % name
		array_len_str += "\t%u, //%s\n" % (pkt.__len__(), name)
		i = 0
		for i in range(pkt.__len__()):
			if (i % 8 == 0) and (i != 0):
				fprintf(fo, ",\n\t")
			elif (i != 0) :
			        fprintf(fo, ", ")
			fprintf(fo, "0x%0.2x" % (pkt.__bytes__()[i]))
		fprintf(fo, "\n};\n")
	fo.flush()

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
	string = string + '#' 
	if itr > 1:
		string = string + end
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

		checksum_override(pkt, 1)
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

def write_dpdk_ipsec_secgw_cfg(fd, sa, i):
	calg = sa.crypt_algo.name
	aalg = sa.auth_algo.name
	cipher_key = ':'.join(hex(x)[2:] for x in sa.crypt_key)
	if calg == 'AES-GCM':
		cipher_key = cipher_key + ':' + ':'.join(hex(x)[2:] for x in sa.crypt_salt)
	auth_key = None
	if calg != 'AES-GCM':
		auth_key = ':'.join(hex(x)[2:] for x in sa.auth_key)
	offloadopt = 'type inline-protocol-offload port_id 0'

	ip4 = ipaddress.ip_address(ipdststart)
	ip4 = ip4 + (i << 8)
	ip6 = ipaddress.ip_address("::" + ipdststart)
	ip6 = ip6 + (i << 8)
	if inb_ipsec != 0:
		if ipv4_proto != 0:
			fprintf(fd, 'sp ipv4 in esp protect %u pri 1 dst %s/24 sport 0:65535	dport 0:65535\n' % (sa.spi, str(ip4)))
		else:
			fprintf(fd, 'sp ipv6 in esp protect %u pri 1 dst %s/120 sport 0:65535 dport 0:65535\n' % (sa.spi, str(ip6)))
		if calg == 'AES-GCM':
			fprintf(fd, 'sa in %u aead_algo aes-128-gcm aead_key %s ' % (sa.spi, cipher_key))
		else:
			fprintf(fd, 'sa in %u cipher_algo aes-128-cbc cipher_key %s auth_algo sha1-hmac auth_key %s ' % (sa.spi, cipher_key, auth_key))
		fprintf(fd, 'mode %s %s\n' % (mode, offloadopt))
	else:
		if ipv4_proto != 0:
			fprintf(fd, 'sp ipv4 out esp protect %u pri 1 dst %s/24 sport 0:65535 dport 0:65535\n' % (sa.spi, str(ip4)))
		else:
			fprintf(fd, 'sp ipv6 out esp protect %u pri 1 dst %s/120 sport 0:65535 dport 0:65535\n' % (sa.spi, str(ip6)))
		if calg == 'AES-GCM':
			fprintf(fd, 'sa out %u aead_algo aes-128-gcm aead_key %s ' % (sa.spi, cipher_key))
		else:
			fprintf(fd, 'sa out %u cipher_algo aes-128-cbc cipher_key %s auth_algo sha1-hmac auth_key %s ' % (sa.spi, cipher_key, auth_key))
		fprintf(fd, 'mode %s %s\n' % (mode, offloadopt))

	if i == ipsec_sas - 1:
		ip4 = ipaddress.ip_address(ipdststart)
		ip6 = ipaddress.ip_address("::" + ipdststart)
		fprintf(fd, 'neigh port 0 11:22:33:44:55:66\n')
		if ipv4_proto != 0:
			fprintf(fd, 'rt ipv4 dst %s/16 port 0\n' % str(ip4))
		else:
			fprintf(fd, 'rt ipv6 dst %s/120 port 0\n' % str(ip6))
		fprintf(fd, 'rt ipv4 dst 1.1.0.0/16 port 0\n')
	return

# Helper functions
def tun_ip():
	return Ether(src=smac,dst=dmac)/IP(dst=tundip,src=tunsip,chksum=0xdead)

def tun_ip6():
	return Ether(src=smac,dst=dmac)/IPv6(dst=tundip6,src=tunsip6)

def tun_ip_udp(s_port, d_port):
	return Ether(src=smac,dst=dmac)/IP(dst=tundip,src=tunsip, chksum=0xdead)/UDP(dport=int(d_port), sport=int(s_port), chksum=0xdead)

def tun_ip6_udp(s_port, d_port):
	return Ether(src=smac,dst=dmac)/IPv6(dst=tundip6, src=tunsip6)/UDP(dport=int(d_port), sport=int(s_port), chksum=0xdead)

def in_ip_tcp(d_ip, s_port, d_port):
	if inner_checksum_dontcare == 0:
		return IP(dst=d_ip,chksum=0xbeef, ttl=(1,1))/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags,chksum=0xdead)
	else:
		return IP(dst=d_ip, ttl=(1,1))/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags)

def in_ip6_tcp(d_ip6, s_port, d_port):
	if inner_checksum_dontcare == 0:
		return IPv6(src=sip6,dst=d_ip6)/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags,chksum=0xdead)
	else:
		return IPv6(src=sip6,dst=d_ip6)/TCP(dport=int(d_port), sport=int(s_port), flags=tcp_flags)

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
parser.add_argument("-w", "--write-pcap", type=str, help="Write to PCAP",
		    required=False, default=None)
parser.add_argument("--minsize", type=int, help="Min pkt size",
		    required=False, default=minsize)
parser.add_argument("--maxsize", type=int, help="Max pkt size",
		    required=False, default=maxsize)
parser.add_argument("--sizeinc", type=int, help="Pkt size increment per burst",
		    required=False, default=sizeinc)
parser.add_argument("--ipsec-sas", type=int, help="IPSec SA's to create",
		    required=False, default=ipsec_sas)
parser.add_argument("--accept-plain", help="Accept plain pkts received with ipsec outbound",
		    required=False, action="store_true")
parser.add_argument("--transport", help="Transport mode esp", required=False,
		    action="store_true")
parser.add_argument("--esn", help="ESN enable", required=False,
		    action="store_true")
parser.add_argument("--dmac", type=str, help="DUT DMAC",
		    required=False, default=dmac)
parser.add_argument("--dip", type=str, help="DUT DIP",
		    required=False)
parser.add_argument("--ipsec-v6-tunnel", help="IPsec V6 tunnel", required=False,
		    action="store_true")
parser.add_argument("--cipher", type=str, help="Cipher Algo",
		    required=False)
parser.add_argument("--auth", type=str, help="Auth Algo",
		    required=False)
parser.add_argument("--fragment", type=int, help="Fragment outer L3 packet with LEN",
		    required=False, default=fragment_size)

write_to_pcap = 0
capture_name = None
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
if args.ipsec_sas:
	ipsec_sas = args.ipsec_sas
if args.accept_plain:
	outb_accept_plain = 1
	opt_str = opt_str + "outb_accept_plain=1 "
if args.transport:
	transport = 1
	opt_str = opt_str + "transport=1 "
if args.write_pcap:
	write_to_pcap = 1
	capture_name = args.write_pcap
	capture_rx = 0
if args.esn:
	esn_en = 1
	opt_str = opt_str + "esn_en=1 "
if args.dmac:
	dmac = args.dmac
if args.dip:
	ipdststart = args.dip
	opt_str = opt_str + "dip=%s " % str(ipdststart)
if args.ipsec_v6_tunnel:
	ipsec_v6_tunnel = 1
	opt_str = opt_str + "ipsec_v6_tunnel=1 "
if args.fragment != 0:
	fragment_size = args.fragment
	opt_str = opt_str + "fragment=%u " % fragment_size

sizeinc = args.sizeinc

if args.proto:
	for key in opt_dict.keys():
		opt_dict[key]=0

	ipv4_proto = 0
	ipv6_proto = 0
	# Overriding default bool options when args are given
	x = str(args.proto)
	for k in x.split(','):
		reObj = re.compile(k)
		for key in opt_dict.keys():
			if (reObj.match(key)):
				opt_dict[key]=1
			if opt_dict[key] != 1:
				continue
			if key.startswith("ipv4"):
				ipv4_proto = 1
			else:
				ipv6_proto = 1

if inb_ipsec or outb_ipsec:
	opt_str = opt_str + "ipsec_sas=%u " % ipsec_sas

opt_str = opt_str + "pkt_bursts=%u flows=%u burst_size=%u " % (pkt_bursts, flows, burst_size)
opt_str = opt_str + "minsize=%u maxsize=%u sizeinc=%u" % (minsize, maxsize, sizeinc)
printf("DMAC       : %s\n" % str(dmac))
if write_to_pcap != 0:
	printf("Capture file: tr_files/%s\n" % capture_name)
else:
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

if os.path.isfile(str(capture_name)):
	os.remove(str(capture_name))

def signal_handler(sig, frame):
	print('You pressed Ctrl+C!. Killing tcpdump!!!')
	os.kill(full_sent.pid, signal.SIGKILL)
	os.kill(full_recv.pid, signal.SIGKILL)
	sys.exit(0)

# Start a full capture if requested
if capture_rx != 0:
	if os.path.isfile('full-sent.pcap'):
		os.remove('full-sent.pcap')
	if os.path.isfile('full-recv.pcap'):
		os.remove('full-recv.pcap')
	full_recv = subprocess.Popen(['tcpdump', '-U', '--immediate-mode', '-i', str(ethdev_name),
				'-w', 'full-recv.pcap', '-s 0', '-Q', 'in' ], stdout=subprocess.PIPE, stderr=DEVNULL)
	full_sent = subprocess.Popen(['tcpdump', '-U', '--immediate-mode', '-i', str(ethdev_name),
				'-w', 'full-sent.pcap', '-s 0', '-Q', 'out'], stdout=subprocess.PIPE, stderr=DEVNULL)
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
	if transport == 1:
		mode = "transport"
		hdr=None
	else:
		if ipsec_v6_tunnel == 0:
			mode = "ipv4-tunnel src %s dst %s" % (tunsip, tundip)
		else:
			mode = "ipv6-tunnel src ::%s dst ::%s" % (tunsip, tundip)
		hdr=IP(src=tunsip, dst=tundip)
	calg = 'AES-GCM'
	ckey = b'sixteenbytes keydpdk'
	aalg = None
	akey = None
	if args.cipher != None:
		calg = args.cipher
	if args.auth != None:
		aalg = args.auth

	if calg == 'AES-GCM':
		ckey = b'sixteenbytes keydpdk'
	else:
		ckey = b'sixteenbytes key'
	if aalg == "HMAC-SHA1-96":
		akey =	b'\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0'

	sa = SecurityAssociation(ESP, spi=int(spi), crypt_algo=calg,
				 crypt_key=ckey, auth_algo=aalg, auth_key=akey,
				 tunnel_header=hdr, esn_en=esn_en)
	sessions[i] = sa
	# Write out DPDK conf for the same
	write_dpdk_ipsec_secgw_cfg(gw_fd, sa, i)

if ipsec_sas != 0:
	gw_fd.close()
	if write_to_pcap != 0:
		print("IPSec-GW conf stored at tr_files/%s." % ipsec_secgw_fname)
	else:
		c = input("IPSec-GW conf stored at tr_files/%s, hit any key to continue:" % ipsec_secgw_fname)

sa = sessions[0]
next_sa = sa
size = minsize

a = [None] * 1
a6 = [None] * 1
a[0] = ipaddress.ip_address(ipdststart)
a6[0] = ipaddress.ip_address("::" + ipdststart)

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
			pkt = Ether(src=smac,dst=dmac,type=0x88f7)/"\x00\x02"
			string = pkt_data_str(set_string, 'IPv4PTP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPv4 TCP
		if ipv4_tcp != 0:
			pkt = Ether(src=smac,dst=dmac)/IP(dst=dip, src=sip, chksum=0xbeef, ttl=(1,1))/TCP(dport=int(dport), sport=pkttype, flags=tcp_flags,chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4 UDP
		if ipv4_udp != 0:
			pkt = Ether(src=smac,dst=dmac)/IP(dst=dip,src=sip, chksum=0xbeef, ttl=(1,1))/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv4UDP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV4 SCTP
		if ipv4_sctp != 0:
			pkt = Ether(src=smac,dst=dmac)/IP(dst=dip,src=sip,chksum=0xbeef, ttl=(1,1))/SCTP(dport=int(dport), sport=pkttype, chksum=0)
			string = pkt_data_str(set_string, 'IPv4SCTP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPv6 TCP
		if ipv6_tcp != 0:
			pkt = Ether(src=smac,dst=dmac)/IPv6(dst=dip6, src=sip6)/TCP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6 UDP
		if ipv6_udp != 0:
			pkt = Ether(src=smac,dst=dmac)/IPv6(dst=dip6, src=sip6)/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv6UDP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		if ipv6_ext_udp != 0:
			pkt = Ether(src=smac,dst=dmac)/IPv6(dst=dip6, src=sip6)
			pkt = pkt / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt() / IPv6ExtHdrDestOpt() / IPv6ExtHdrRouting()
			pkt = pkt / UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'IPv6ExtUDP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#IPV6 SCTP
		if ipv6_sctp != 0:
			pkt = Ether(src=smac,dst=dmac)/IPv6()/SCTP(dport=int(dport), sport=pkttype, chksum=0xdead)
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
			pkt = Ether(src=smac,dst=dmac)/Dot1Q()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1QIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1Q IPv6 TCP
		if dot1q_ipv6_tcp != 0:
			pkt = Ether(src=smac,dst=dmac)/Dot1Q()/IPv6(dst=dip6, src=sip6)/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'Dot1QIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1Q/IPV4/GRE/IPV4/TCP
		if dot1q_ipv4_gre_ipv4_tcp != 0:
			pkt = Ether(src=smac,dst=dmac)/Dot1Q()/IP(chksum=0xdead)/GRE(proto=0x0800)/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1QIPv4GREIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1AD Dot1Q IPv4 TCP
		if dot1ad_dot1q_ipv4_tcp != 0:
			pkt = Ether(src=smac,dst=dmac)/Dot1AD()/Dot1Q()/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1ADDot1QIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1AD Dot1Q IPv6 TCP
		if dot1ad_dot1q_ipv6_tcp != 0:
			pkt = Ether(src=smac,dst=dmac)/Dot1AD()/Dot1Q()/IPv6(dst=dip6, src=sip6)/UDP(dport=int(dport), sport=pkttype, chksum=0xdead)
			string = pkt_data_str(set_string, 'Dot1ADDot1QIPv6TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

		#Dot1AD/Dot1Q/IPV4/GRE/IPV4/TCP
		if dot1ad_dot1q_ipv4_gre_ipv4_tcp != 0:
			pkt = Ether(src=smac,dst=dmac)/Dot1AD()/Dot1Q()/IP(chksum=0xdead)/GRE(proto=0x0800)/in_ip_tcp(dip, pkttype, dport)
			string = pkt_data_str(set_string, 'Dot1ADDot1QIPv4GREIPv4TCP', size - len(pkt))
			pkt = pkt / Raw(string)
			pkt_list += pkt
			pkttype += 1

	# L3 Fragment if needed
	if fragment_size != 0:
		tmp_list = []
		for pkt in pkt_list:
			if pkt.firstlayer()[1].name == 'IPv6' or pkt.firstlayer()[2].name == 'IPv6':
				tmp_list += pkt.fragment6(fragsize=fragment_size)
			else:
				tmp_list += pkt.fragment(fragsize=fragment_size)
		pkt_list = tmp_list

	new_pkt_list = []
	for pkt in pkt_list:
		checksum_override(pkt, good_checksum)
		if inb_ipsec != 0:
			sa = next_sa

			l = pkt[Ether].payload
			if pkt.firstlayer()[1].name == '802.1Q':
				l = pkt[Dot1Q].payload
				new_pkt = Ether(src=smac,dst=dmac)/Dot1Q()/sa.encrypt(l)
				new_pkt_list += new_pkt
			else:
				new_pkt = Ether(src=smac,dst=dmac)/sa.encrypt(l)
				new_pkt_list += new_pkt
		else:
			new_pkt_list += pkt

	# Dump packets to pkts.h
	if dump != 0:
		for pkt in new_pkt_list:
			pkt_data_dump(pkt)

	# Send burst
	if write_to_pcap == 0:
		sendp(new_pkt_list, count=1, iface=str(name), verbose=0, return_packets=0)
	else:
		wrpcap(str(capture_name), new_pkt_list, append=True)

	#printf("Sent pkt of size %u\n" % size)
	#time.sleep(4)
	count = count + 1

	# Move to next sa 
	if  ipsec_sas != 0:
		sa_i = count % ipsec_sas
		next_sa = sessions[sa_i]
		a[0] = ipaddress.ip_address(ipdststart)
		a6[0] = ipaddress.ip_address("::" + ipdststart)
		a[0] = a[0] + (sa_i << 8)
		a6[0] = a6[0] + (sa_i << 24)

	total_pkts_count = total_pkts_count + len(pkt_list)
	printf("\r")
	printf("Sent packets %u/%u" % (total_pkts_count, test_pkts_count))
	# Reset ip series when flows reached
	if count % flows == 0:
		a[0] = ipaddress.ip_address(ipdststart)
		a6[0] = ipaddress.ip_address("::" + ipdststart)
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
	os.kill(full_sent.pid, signal.SIGINT)
	os.kill(full_recv.pid, signal.SIGINT)
	full_sent.wait()
	full_recv.wait()

# Split sent and recv
#	if os.path.isfile('full-sent.pcap'):
#		os.remove('full-sent.pcap')
#	if os.path.isfile('full-recv.pcap'):
#		os.remove('full-recv.pcap')

#	sent_filter = "ether dst %s" % dutmac.lower()
#	recv_filter = "not ether dst %s" % dutmac.lower()
#	s = subprocess.Popen(['tcpdump', '-r', 'full.pcap',
#				'-w', 'full-sent.pcap', sent_filter], stdout=subprocess.PIPE,
#				stderr=DEVNULL)

#	r = subprocess.Popen(['tcpdump', '-r', 'full.pcap',
#				'-w', 'full-recv.pcap', recv_filter], stdout=subprocess.PIPE,
#				stderr=DEVNULL)
#	s.wait();
#	r.wait();

	if name != '':
#		os.rename('full.pcap', '%s-full.pcap' % name)
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
			sent_list += Ether(src=smac,dst=dmac)/sa.decrypt(pkt[Ether].payload)
		# Write plain pkts out
		wrpcap('full-sent.pcap', sent_list)

	if outb_ipsec != 0:
		os.rename('full-recv.pcap', 'full-recv-cipher.pcap')
		cipher_recv_list = recv_list
		recv_list = []
		for pkt in cipher_recv_list:
			try:
				spi = pkt[ESP].spi
				idx = int(spi) - int(spi_base)
				sa = sessions[idx]
				recv_list += Ether(src=smac,dst=dmac)/sa.decrypt(pkt[Ether].payload)
			except:
				if outb_accept_plain == 0:
					printf("Received unexpected plain pkts\n")
					pkt.show()
					exit(1)
				outb_plain_pkts += 1
				recv_list += pkt
				continue
		# Write plain pkts out
		wrpcap('full-recv.pcap', recv_list)

	for pkt in sent_list:
		dump_pkt_load(pkt, fds)

	for pkt in recv_list:
		dump_pkt_load(pkt, fdr)

	if recv_sanity != 0:
		sniff_and_check_sanity(sent_list, recv_list)
		if outb_accept_plain != 0:
			printf("\rResult as expected for %d/%d pkts(%d plain pkts)\n" % (good_pkts_count, total_pkts_count, outb_plain_pkts))
		else:
			printf("\rResult as expected for %d/%d pkts\n" % (good_pkts_count, total_pkts_count))
		if total_pkts_count != good_pkts_count:
			printf("Please check sent.txt, expect.txt, recv.txt for errors\n")
