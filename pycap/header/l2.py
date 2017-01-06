
class L2Hdr(object):
    pass
    
    
class EthHdr(L2Hdr):
    def __init__(self):
        self.srcMac = ''
        self.dstMac = ''
        self.etherType = None
        self.payload = None
        
