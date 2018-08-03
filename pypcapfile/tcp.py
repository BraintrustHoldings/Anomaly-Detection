"""
TCP transport definition
"""

import binascii
import ctypes
import struct

class TCP(ctypes.Structure):
    """
    Represents a TCP packet
    """

    _fields_ = [('src_port', ctypes.c_ushort),  # source port
                ('dst_port', ctypes.c_ushort),  # destination port
                ('seqnum', ctypes.c_uint),      # sequence number
                ('acknum', ctypes.c_uint),      # acknowledgment number
                ('data_offset', ctypes.c_uint), # data offset in bytes
                ('reserved', ctypes.c_ushort),  # data offset in bytes
                ('flags', ctypes.c_ushort),     # all the flas except ECN as one byte
                ('ecn', ctypes.c_bool),         # ECN
                ('cwr', ctypes.c_bool),         # CWR
                ('ece', ctypes.c_bool),         # ECE
                ('urg', ctypes.c_bool),         # URG
                ('ack', ctypes.c_bool),         # ACK
                ('psh', ctypes.c_bool),         # PSH
                ('rst', ctypes.c_bool),         # RST
                ('syn', ctypes.c_bool),         # SYN
                ('fin', ctypes.c_bool),         # FIN
                ('win', ctypes.c_ushort),       # window size
                ('sum', ctypes.c_ushort),       # checksum
                ('opt', ctypes.c_char_p),       # options
                ('payload', ctypes.c_char_p)]   # packet payload

    tcp_min_header_size = 20

    def __init__(self, packet, layers=0):
        fields = struct.unpack("!HHIIBBHHH", packet[:self.tcp_min_header_size])
        self.src_port = fields[0]
        self.dst_port = fields[1]
        self.seqnum = fields[2]
        self.acknum = fields[3]
        
        # Note: Data offset is stored in the first 4 bits of the 1 byte fields[4].  The next
        # 3 bits are reserved and the last bit contains the ECN flag.
        self.data_offset = 4 * (fields[4] >> 4)
		
        # Store the last 4 bits of fields[4] in reserved.  The last bit contains the ECN flag.
        self.reserved = fields[4] & 0xf

		# Get the flags from the 9 bits starting with the last bit of fields[4].
        self.flags = fields[5] 
        self.ecn = fields[4] & 1
        self.cwr = fields[5] & 128
        # 3 bits are reserved and the last bit contains the ECN flag.
        self.reserved = fields[4] & 0xf

		# Get the flags from the 9 bits starting with the last bit of field[4].
        self.flags = fields[5] 
        self.ecn = fields[4] & 1
        self.cwr = fields[5] & 128
        self.ece = fields[5] & 64
        self.urg = fields[5] & 32
        self.ack = fields[5] & 16
        self.psh = fields[5] & 8
        self.rst = fields[5] & 4
        self.syn = fields[5] & 2
        self.fin = fields[5] & 1

        self.win = fields[6]
        self.sum = fields[7]
        urg_offset = 4 * fields[8] # rarely used

        if self.data_offset < 20:
            self.opt = b''
            self.payload = b''
        else:
            self.opt = ctypes.c_char_p(binascii.hexlify(packet[20:self.data_offset]))
            self.payload = ctypes.c_char_p(binascii.hexlify(packet[self.data_offset:]))

    def __str__(self):
        packet = 'tcp %s packet from port %d to port %d carrying %d bytes'
        str_flags = ''
        if self.syn: str_flags += 'S'
        if self.ack: str_flags += 'A'
        if self.rst: str_flags += 'R'
        if self.fin: str_flags += 'F'
        if self.urg: str_flags += 'U'
        if self.psh: str_flags += 'P'
        if self.cwr: str_flags += 'C'
        if self.ece: str_flags += 'E'
        if self.ecn: str_flags += 'N'
        packet = packet % (str_flags, self.src_port, self.dst_port, (len(self.payload) / 2))
        return packet

    def __len__(self):
        return max(self.data_offset, self.tcp_min_header_size) + len(self.payload) / 2

