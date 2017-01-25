from .. import util



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
        self.rst = None
        self.syn = None
        self.fin = None
        self.windows = None
        self.checksum = None
        self.urgentPointer = None
        self.options = None
        self.padding = None
        self.payload = None

    def printHdr(self):
        util.printHdrName('TCP')
        util.printHdr('srcPort', self.srcPort)
        util.printHdr('dstPort', self.dstPort)
        util.printHdr('sequence number', self.seqNumber)
        util.printHdr('reserved', self.reserved)
        util.printHdr('urg', self.urg)
        util.printHdr('ack', self.ack)
        util.printHdr('psh', self.psh)
        util.printHdr('rst', self.rst)
        util.printHdr('syn', self.syn)
        util.printHdr('fin', self.fin)
        util.printHdr('windows', self.windows)
        util.printHdr('checksum', self.checksum)
        util.printHdr('urgent pointer', self.urgentPointer)
        util.printHdr('options', self.options)
        util.printHdr('padding', self.padding)

        

class UDPHdr(L4Hdr):
    def __init__(self):
        self.srcPort = None
        self.dstPort = None
        self.length = None
        self.checksum = None
        self.payload = None
        
        
    def printHdr(self):
        util.printHdrName('UDP')
        util.printHdr('srcPort', self.srcPort)
        util.printHdr('dstPort', self.dstPort)
        util.printHdr('length', self.length)
        util.printHdr('checksum', self.checksum)



# ICMP is not L4 but L3
class ICMPHdr(L4Hdr):
    def __init__(self):
        self.type = None
        self.code = None
        self.checksum = None
        self.unused = None
        self.InternetHdr = None


    def printHdr(self):
        util.printHdrName('ICMP')
        util.printHdr('type', self.type)
        util.printHdr('code', self.code)
        util.printHdr('checksum', self.checksum)
        util.printHdr('unused', self.unused)
 
