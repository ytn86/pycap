
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

class IPv6Hdr(L3Hdr):
    def __init__(self):
        self.version = None        # 4bit
        self.trafficClass = None   # 8bit
        self.flowLabel = None      # 20bit
        self.hdrLen = None         # 16bit
        self.nextHdr = None       # 8bit
        #self.protocol = None       # 8bit
        self.hopLim = None         # 8bit
        self.srcIP = None          # 128bit
        self.dstIP = None          # 128bit
        self.routingHdr = None     # extra Header

        
        #self.protocol = self.nextHdr # alias
        
