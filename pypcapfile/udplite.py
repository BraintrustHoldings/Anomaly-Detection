"""
UDPLITE transport definition
This protocol is defined here: https://tools.ietf.org/html/rfc3828
"""

import binascii
import ctypes
import struct

class UDPLITE(ctypes.Structure):
    """
    Represents a UDPLITE packet
    """

    _fields_ = [('src_port', ctypes.c_ushort),  # source port
                ('dst_port', ctypes.c_ushort),  # destination port
                ('coverage', ctypes.c_ushort),  # number of octets, starting with the header, that are covered by checksum
                ('checksum', ctypes.c_ushort),  # checksum
                ('payload', ctypes.c_char_p)]   # packet payload

    udp_header_size = 8

    def __init__(self, packet, layers=0):
        fields = struct.unpack("!HHHH", packet[:self.udp_header_size])
        self.src_port = fields[0]
        self.dst_port = fields[1]
        self.coverage = fields[2]
        self.checksum = fields[3]
        self.payload = ctypes.c_char_p(binascii.hexlify(packet[self.udp_header_size:]))

    def __str__(self):
        packet = 'udplite packet from port %d to port %d carrying %d bytes'
        packet = packet % (self.src_port, self.dst_port, (len(self.payload) / 2))
        return packet

    def __len__(self):
        return self.udp_header_size + len(self.payload)

