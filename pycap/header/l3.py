from .. import util



class L3Hdr(object):
    pass

class IPv4Hdr(L3Hdr):
    def __init__(self):
        self.version = None
        self.hdrLen = None
        self.serviceType = None
        self.totalLen = None
        self.ident = None
        self.flags = None
        self.fragmentOffset = None
        self.TTL = None
        self.protocol = None
        self.checksum = None
        self.srcIP = ''
        self.dstIP = ''
        self.options = None
        self.padding = None
        self.payload = None

    def printHdr(self):
        util.printHdrName('IPv4')
        util.printHdr('version', self.version)
        util.printHdr('header length', self.hdrLen)
        util.printHdr('service type', self.serviceType)
        util.printHdr('total length', self.totalLen)
        util.printHdr('ident', self.ident)
        util.printHdr('flags', self.flags)
        util.printHdr('fragment offset', self.fragmentOffset)
        util.printHdr('TTL', self.TTL)
        util.printHdr('protocol', self.protocol)
        util.printHdr('checksum', self.checksum)
        util.printHdr('srcIP', self.srcIP)
        util.printHdr('dstIP', self.dstIP)
        util.printHdr('options', self.options)
        util.printHdr('padding', self.padding)

        
class IPv6Hdr(L3Hdr):
    def __init__(self):
        self.version = None        # 4bit
        self.trafficClass = None   # 8bit
        self.flowLabel = None      # 20bit
        self.hdrLen = None         # 16bit
        self.nextHdr = None       # 8bit
        self.hopLim = None         # 8bit
        self.srcIP = None          # 128bit
        self.dstIP = None          # 128bit
        self.routingHdr = None     # extra Header

        
    def printHdr(self):
        util.printHdrName('IPv6')
        util.printHdr('version', self.version)
        util.printHdr('traffic class', self.trafficClass)
        util.printHdr('flow label', self.flowLabel)
        util.printHdr('header length', self.hdrLen)
        util.printHdr('next header', self.nextHdr)
        util.printHdr('hop limit', self.hopLim)
        util.printHdr('srcIP', self.srcIP)
        util.printHdr('dstIP', self.dstIP)



class ARPHdr(L3Hdr):
    def __init__(self):
        self.hwType = None          #16 bit
        self.protoType = None       #16 bit
        self.hwAddrLen = None       #8 bit
        self.protoAddrLen = None    #8 bit
        self.opCode = None          #16 bit
        self.senderHwAddr = None    #48 bit
        self.senderProtoAddr = None #32 bit
        self.targetHwAddr = None    #48 bit
        self.targetProtoAddr = None #32 bit


    def printHdr(self):
        util.printHdrName('ARP')
        util.printHdr('Hardware type', self.hwType)
        util.printHdr('protocol type', self.protoType)
        util.printHdr('Hardware address length', self.hwAddrLen)
        util.printHdr('protocol address length', self.protoAddrLen)
        util.printHdr('opcode', self.opCode)
        util.printHdr('sender hardware address', self.senderHwAddr)
        util.printHdr('sender protocol address', self.senderProtoAddr)
        util.printHdr('target hardware address', self.targetHwAddr)
        util.printHdr('target protocol address', self.targetProtoAddr)
