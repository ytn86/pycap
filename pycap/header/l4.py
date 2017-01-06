
class L4Hdr(object):
    pass

class TCPHdr(L4Hdr):
    def __init__(self):
        self.srcPort = None
        self.dstPort = None
        self.seqNumber = None
        self.ackNumber = None
        self.dataOffset = None
        self.reserved = None 
        self.urg = None
        self.ack = None
        self.psh = None
        self.srcPort = None
        self.rst = None
        self.syn = None
        self.fin = None
        self.windows = None
        self.checksum = None
        self.urgentPointer = None
        self.options = None
        self.padding = None
        self.payload = None

        

class UDPHdr(L4Hdr):
    def __init__(self):
        self.srcPort = None
        self.dstPort = None
        self.length = None
        self.checksum = None
        self.payload = None
        
            
class ICMPHdr(L4Hdr):
    def __init__(self):
        self.type = None
        self.code = None
        self.checksum = None
        self.unused = None
        self.InternetHdr = None
