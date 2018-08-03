# This script parses PCAP files using the Python library pypcapfile 0.12.0.  This library came 
# from pypi.org and was installed using "pip install pypcapfile".  Sample code for using the
# library can be found on https://pypi.org/project/pypcapfile.  
#
# The first 3 sample PCAP files were downloaded from https://wiki.wireshark.org/SampleCaptures#TCP.  
# The last PCAP file is a trimmed down version of a PCAP file found on 
# https://www.netresec.com/?page=MACCDC.
#
# The output of this script can be compared with the data packets viewed with Wireshark.

from pcapfile import savefile

def output_packets(fname, num_packets):
	print("PCAP file is ", fname)

	fp = open(fname, 'rb')
	pcap = savefile.load_savefile(fp, layers=3, verbose=True)
	print(pcap)
	
	if len(pcap.packets) < num_packets:
		max_packet = len(pcap.packets)
	else:
		max_packet = num_packets

	for i in range(0, max_packet):
		eth_frame = pcap.packets[i]
		print(eth_frame)
		type = eth_frame.packet.type
		if type == 0x0800:  # IP 
			ip_packet = eth_frame.packet.payload
			print(ip_packet)
			layer3_packet = ip_packet.payload
			print(layer3_packet)
		elif type == 0x8100:  # VLAN
			vlan_packet = eth_frame.packet.payload
			print(vlan_packet)
			ip_packet = vlan_packet.payload
			print(ip_packet)
			layer3_packet = ip_packet.payload
			print(layer3_packet)
		print()

output_packets("C:\\Users\\kromanik\\IRAD\\Pcap\\tcp-ecn-sample.pcap", 15)
output_packets("C:\\Users\\kromanik\\IRAD\\Pcap\\udp_lite_normal_coverage_8-20.pcap", 15)
output_packets("C:\\Users\\kromanik\\IRAD\\Pcap\\PPP-config.pcap", 15)
output_packets("C:\\Users\\kromanik\\IRAD\\Pcap\\maccdc2012_00000_trim.pcap", 15)