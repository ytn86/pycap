from .. import util



class L2Hdr(object):
    pass
    
    
class EthHdr(L2Hdr):
    def __init__(self):
        self.srcMac = ''
        self.dstMac = ''
        self.etherType = None
        self.payload = None
        
    def toString(self):
        util.printHdrName('Ethernet')
        util.printHdr('srcMac', self.srcMac)
        util.printHdr('dstMac', self.dstMac)
        util.printHdr('etherType', hex(self.etherType))
        
