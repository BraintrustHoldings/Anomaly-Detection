# This program implements the anomaly detection algorithm described in the whitepaper 
# "Network Traffic Anomaly Detection in Embedded Systems" using a PCAP file for input.
#
# The algorithm implemented here differs from the one described in the paper in how it 
# scores fields.  The time score and frequency score have maximum values of maxTraining,
# which is the number of packets used for training.  The normalized anomaly score is
# obtained by dividing by maxTraining**2.
# 
# This program was tested on the input file maccdc2012_00000_trim.pcap, which was 
# obtained by running the trim_file.py script on the PCAP file maccdc2012_00000.pcap 
# obtained from the web page https://www.netresec.com/?page=MACCDC.  The file was
# trimmed to 10,000,000 bytes.
#
# This program allows a user to experiment with changing or extending the algorithm.

import sys
from pcapfile import savefile

maxFldId = 10
fieldData = {}
valueData = {}

sizePcap = 0
numPackets = 0
numTraining = 0
maxPackets = 10000
maxTraining = 400
threshold = 0.9
totalAnomalies = 0

lastSeenIdx = 0
totalSeenIdx = 1


# This function can be used for debugging.
def printFieldData():
    global fieldData

    for fldKey in fieldData.keys():
        print(fldKey, fieldData[fldKey])


# Open the PCAP file and return the object that holds the data
def openPcapFile(fname):
    global sizePcap
	
    print("PCAP file is ", fname)

    fp = open(fname, 'rb')

    # The following call to the pycapfile library parses packets in the given PCAP
    # file down to the third  layer in the TCP/IP model: layer1 = data link (ethernet),
    # layer2 = network (IP), layer3 = transport(TCP, UDP).  It saves the parsed packets
    # in the list pcap.packets.
    pcap = savefile.load_savefile(fp, layers=3)
    sizePcap = len(pcap.packets) 

    print(pcap)
    return pcap


# Return the next packet from the PCAP file
def readPacket():
    global pcap
    global numPackets, sizePcap
	
    if numPackets < sizePcap:
        return pcap.packets[numPackets]
    else:
        print("No more packets in PCAP file")
        return None


# Parse and return fields from a single layer of a packet
def parseFields(layer, protocol):
    fields = []
    if protocol == 'IPv4':
        fields.append(["ip_ver",layer.v])
        fields.append(["ip_hlen",layer.hl])
        fields.append(["ip_tos",layer.tos])
        fields.append(["ip_len",layer.len])
        fields.append(["ip_id",layer.id])
        fields.append(["ip_flags",layer.flags])
        fields.append(["ip_off",layer.off])
        fields.append(["ip_ttl",layer.ttl])
        fields.append(["ip_proto",layer.p])
        fields.append(["ip_src",layer.src])
        fields.append(["ip_dst",layer.dst])
    elif protocol == 'TCP':
        fields.append(["tcp_srcport",layer.src_port])
        fields.append(["tcp_dstport",layer.dst_port])
        fields.append(["tcp_seqnum",layer.seqnum])
        fields.append(["tcp_acknum",layer.acknum])
        fields.append(["tcp_doff",layer.data_offset])
        fields.append(["tcp_res",layer.reserved])
        fields.append(["tcp_flags",layer.flags])
    elif protocol == 'UDP':
        fields.append(["udp_srcport",layer.src_port])
        fields.append(["udp_dstport",layer.dst_port])
        fields.append(["udp_len",layer.len])
    elif protocol == 'UDPLITE':
        fields.append(["udpl_srcport",layer.src_port])
        fields.append(["udpl_dstport",layer.dst_port])
        fields.append(["udpl_cover",layer.coverage])

    return fields


# Return a protocol string based on the value of the protocol field of a packet layer
def getProtocol(protocol):
    if protocol == 0x0800:
        return 'IPv4'
    elif protocol == 0x8100:
        return 'VLAN'
    elif protocol == 0x11:
        return 'UDP'
    elif protocol == 0x88:
        return 'UDPLITE'
    elif protocol == 0x06:
        return 'TCP'
    else:
        return 'unknown'
  

 # Parse and return the fields from layers 2 and 3 of a packet
def parsePacket(layer1_packet):
    fields = []
	
    protocol = getProtocol(layer1_packet.packet.type)
    if protocol == 'IPv4':
        layer2_packet = layer1_packet.packet.payload
    elif protocol == 'VLAN': # VLAN is between Ethernet and IP
        vlan_packet = layer1_packet.packet.payload
        protocol = getProtocol(vlan_packet.protocol) # Get the layer 2 protocol
        layer2_packet = vlan_packet.payload
    else:
        return None

    fields += parseFields(layer2_packet, protocol)
    layer3_protocol = getProtocol(layer2_packet.p)
    layer3_packet = layer2_packet.payload
    fields += parseFields(layer3_packet, layer3_protocol)
    return fields


# Compute the normalized anomaly score of a field
def scoreField(fld):
    global lastSeenIdx, totalSeenIdx
    global numPackets, maxTraining
    global fieldData, valueData

    fldKey = fld[0]
    fldVal = fld[1]	
    valKey = str(fldKey) + str(fldVal)

    if valKey in valueData.keys():
        timeScore = numPackets - valueData[valKey][lastSeenIdx]
        if timeScore > maxTraining:
            timeScore = maxTraining
        frequencyScore = float(fieldData[fldKey][totalSeenIdx]) / valueData[valKey][totalSeenIdx]
        if frequencyScore > maxTraining:
            frequencyScore = float(maxTraining)
    else:
        timeScore = maxTraining
        frequencyScore = float(maxTraining)
    anomalyScore = timeScore * frequencyScore
    normalScore = anomalyScore / maxTraining**2

    if normalScore > threshold:
        return (1, normalScore)
    else:
        return (0, normalScore)


# Report an anomalous packet
def reportAnomaly(score, packet):
    print("Packet ", numPackets, " had an anomaly score of ", score)
    print(packet)


# Update the fieldData and valueData tables based on a particular field
def processField(fld):
    global lastSeenIdx, totalSeenIdx
    global numPackets, fieldData, valueData

    fldKey = fld[0]
    fldVal = fld[1]	
    if fldKey in fieldData.keys():
        fieldData[fldKey][lastSeenIdx] = numPackets
        fieldData[fldKey][totalSeenIdx] = fieldData[fldKey][totalSeenIdx] + 1
    else:
        fieldData[fldKey] = [numPackets, 1]

    valKey = fldKey + str(fldVal)
    if valKey in valueData.keys():
        valueData[valKey][lastSeenIdx] = numPackets
        valueData[valKey][totalSeenIdx] = valueData[valKey][totalSeenIdx] + 1
    else:
        valueData[valKey] = [numPackets, 1]


# This function does the training phase of the anomaly detection algorithm.
def trainData():
    global numPackets, maxTraining, sizePcap

    while numPackets < maxTraining and numPackets < sizePcap:
        packet = readPacket()
        fields = parsePacket(packet)
        numPackets += 1
        for field in fields:
            processField(field)


# After training, this function checks packets for anomalies
def checkData():
    global numPackets, maxTraining, sizePcap, totalAnomalies

    # The program exits on an error on packet 887.  I didn't have time to figure it out.
    while numPackets < maxPackets and numPackets < sizePcap:
    #while numPackets < maxPackets and numPackets < sizePcap and numPackets < 886:
        packet = readPacket()
        fields = parsePacket(packet)
        numPackets += 1
        anomalies = 0
        anomalyScore = 0

        for field in fields:
            (anomaly, score) = scoreField(field)
            anomalies += anomaly
            if score > anomalyScore:
                anomalyScore = score
            processField(field)
        if anomalies > 0:
            reportAnomaly(anomalyScore, fields)
            totalAnomalies += 1

infile = sys.argv[1]
pcap = openPcapFile(infile)

trainData()
#printFieldData()
checkData()
print("Total anomalies found = ", totalAnomalies)
			

