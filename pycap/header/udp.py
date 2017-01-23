from .. import util



class L7Hdr(object):
    pass


class DHCPHdr(L7Hdr):
    def __init__(self):
        self.op = None      # 8bit
        self.htype = None   # 8bit
        self.hlen = None    # 8bit
        self.hops = None    # 8bit
        self.xid = None     # 32bit
        self.secs = None    # 16bit
        self.flags = None   # 16bit
        self.ciaddr = None  # 32bit
        self.yiaddr = None  # 32bit
        self.siaddr= None   # 32bit
        self.giaddr = None  # 32bit
        self.chaddr = None  # 128bit
        self.sname = None   # 512bit
        self.file = None    # 1024bit
        self.options = None # variable
        

    def toString(self):
        util.printHdrName('DHCP')
        util.printHdr('op', self.op)
        util.printHdr('htype', self.htype)
        util.printHdr('hops', self.hops)
        util.printHdr('xid', self.xid)
        util.printHdr('secs', self.secs)
        util.printHdr('flags', self.flags)
        util.printHdr('ciaddr', self.ciaddr)
        util.printHdr('yiaddr', self.yiaddr)
        util.printHdr('siaddr', self.siaddr)
        util.printHdr('chaddr', self.chaddr)
        util.printHdr('sname', self.sname)
