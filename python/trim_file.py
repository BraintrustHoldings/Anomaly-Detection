# This script can be used to trim a PCAP file that is too big to view in Wireshark.
# It was used on the PCAP file maccdc2012_00000.pcap obtained from this web page:
# https://www.netresec.com/?page=MACCDC

import sys

infile = sys.argv[1]
outfile = sys.argv[2]
num_bytes = int(sys.argv[3])

print("infile = ", infile, " outfile = ", outfile, " num_bytes = ", num_bytes)

ifp = open(infile, 'rb')
ofp = open(outfile, 'wb')
incr = 100
bytes_read = 0

while bytes_read < num_bytes:
	bytes = ifp.read(incr)
	ofp.write(bytes)
	bytes_read += incr

ifp.close()
ofp.flush()
ofp.close()