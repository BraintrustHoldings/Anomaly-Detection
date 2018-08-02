"""
VLAN (Virtual Local Area Network) protocol definition.
"""

import binascii
import ctypes
import struct

from pcapfile.protocols.linklayer.ethernet import payload_type


class VLAN(ctypes.Structure):
    """
    Represents a VLAN packet.
    """
	
    _fields_ = [('id', ctypes.c_ushort),       # identifier (first 3 bits are priority and 4th bit is DEI flag)
                ('protocol', ctypes.c_ushort)] # protocol

    payload = None
    vlan_header_size = 4

    def __init__(self, packet, layers=0):
        fields = struct.unpack("!HH", packet[:self.vlan_header_size])
        self.id = fields[0]
        self.protocol = fields[1]
        self.payload = binascii.hexlify(packet[self.vlan_header_size:])
		
        if layers:
            self.load_network(layers)

    def load_network(self, layers=1):
        """
        Given a VLAN packet, determine the appropriate sub-protocol;
        If layers is greater than zero, determine the type of the payload
        and load the appropriate type of network packet. It is expected
        that the payload is a hexified string. The layers argument determines
        how many layers to descend while parsing the packet. It isn't 
		decremented here because VLAN comes after Ethernet, but they're both
		part of the data link layer.
        """
        if layers:
            ctor = payload_type(self.protocol)[0]
            if ctor:
                ctor = ctor
                payload = binascii.unhexlify(self.payload)
                self.payload = ctor(payload, layers)
            else:
                # if no type is found, do not touch the packet.
                pass

    def __str__(self):
        packet = 'vlan packet with id %d type %s'
        packet = packet % (self.id, payload_type(self.protocol)[1])
        return packet

    def __len__(self):
        return self.vlan_header_size + len(self.payload)

def __call__(packet):
    return VLAN(packet)

