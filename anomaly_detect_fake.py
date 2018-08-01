# This program implements the anomaly detection algorithm described in the whitepaper 
# "Network Traffic Anomaly Detection in Embedded Systems" using fake data packets as input.
#
# The algorithm implemented here differs from the one described in the paper in how it 
# scores fields.  The time score and frequency score have maximum values of maxTraining,
# which is the number of packets used for training.  The normalized anomaly score is
# obtained by dividing by maxTraining**2.
# 
# An initial version of this script used numPackets**2 to normalize anomaly scores.  
# However, this normalization factor waters down results over time.  It causes packets that 
# have been seen previously but rarely occur to eventually not be identified as anomalies.
#
# This program is meant to illustrate the algorithm described in the paper and to allow a 
# user to experiment with changing parts of the algorithm.

maxFldId = 10
fieldData = []

valueData = {}

numPackets = 0
numTraining = 0
maxPackets = 10000
maxTraining = 1000
threshold = 0.9

lastSeenIdx = 0
totalSeenIdx = 1

def initFieldData():
    global fieldData

    for i in range(maxFldId):
        fieldData.append([0,0])

def readFakePacket():
    global numPackets
	
    if numPackets % 1000 == 0: # Create a fake rare packet; some field  values are common
        packet = [[0,2],[1,636],[2,23],[3,"junk"],[4,"hack"],[5,12],[6,14],[7,"hey"],[8,18],[9,101]]
    elif numPackets % 50 == 0: # Create a fake occassioanal packet; shares some values with rare and common
        packet = [[0,2],[1,4],[2,23],[3,88],[4,100],[5,12],[6,144],[7,16],[8,888],[9,101]]
    else: # Create a fake common packet
        packet = [[0,2],[1,4],[2,6],[3,8],[4,10],[5,12],[6,14],[7,16],[8,18],[9,20]]
    return packet

def scoreField(fld):
    global lastSeenIdx, totalSeenIdx
    global numPackets, maxTraining
    global fieldData, valueData

    fldIdx = fld[0]
    fldVal = fld[1]	
    valKey = str(fldIdx) + str(fldVal)

    if valKey in valueData.keys():
        timeScore = numPackets - valueData[valKey][lastSeenIdx]
        if timeScore > maxTraining:
            timeScore = maxTraining
        frequencyScore = float(fieldData[fldIdx][totalSeenIdx]) / valueData[valKey][totalSeenIdx]
        if frequencyScore > maxTraining:
            frequencyScore = float(maxTraining)
    else:
        timeScore = maxTraining
        frequencyScore = float(maxTraining)
    anomalyScore = timeScore * frequencyScore
    normalScore = anomalyScore / maxTraining**2

    #if numPackets % 1000 == 1: # Print scores of rare packets
        #print("field", fldIdx, ":", timeScore, frequencyScore, anomalyScore, normalScore)
    #if numPackets < 1006 or numPackets == 1051: # Print scores of some common packets
        #print("field", fldIdx, ":", timeScore, frequencyScore, anomalyScore, normalScore)
    if normalScore > threshold:
        return (1, normalScore)
    else:
        return (0, normalScore)

def reportAnomaly(score, packet):
    print("The following packet had an anomaly score of ", score)
    print(packet)


def processField(fld):
    global lastSeenIdx, totalSeenIdx
    global numPackets, fieldData, valueData

    fldIdx = fld[0]
    fldVal = fld[1]	
    fieldData[fldIdx][lastSeenIdx] = numPackets
    fieldData[fldIdx][totalSeenIdx] = fieldData[fldIdx][totalSeenIdx] + 1
    valKey = str(fldIdx) + str(fldVal)

    if valKey in valueData.keys():
        valueData[valKey][lastSeenIdx] = numPackets
        valueData[valKey][totalSeenIdx] = valueData[valKey][totalSeenIdx] + 1
    else:
        valueData[valKey] = [numPackets, 1]

def trainData():
    global numPackets, maxTraining
	
    while numPackets < maxTraining:
        packet = readFakePacket()
        numPackets += 1
        for field in packet:
            processField(field)

def checkData():
    global numPackets, maxTraining

    while numPackets < maxPackets:
        packet = readFakePacket();
        numPackets += 1
        anomalies = 0
        anomalyScore = 0

        #if numPackets < 1006 or numPackets == 1051:  # Print some sample packets
            #print("packet[", numPackets, "]=", packet)

        for field in packet:
            (anomaly, score) = scoreField(field)
            anomalies += anomaly
            if score > anomalyScore:
                anomalyScore = score
            processField(field)
        if anomalies > 0:
            reportAnomaly(anomalyScore, packet)

initFieldData()
trainData()
checkData()
			

