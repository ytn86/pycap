#! /usr/bin/env python3

import struct
import binascii
import socket
from .header.l2 import *
from .header.l3 import *
from .header.l4 import *
from .header.l7 import *

class Parser(object):
 
    
    def __init__(self):
        self.l4Parsers = [None]*255
        self.registerIPParser()
 
    def registerIPParser(self):
        self.l4Parsers[6] = self.parseTCPHdr
        self.l4Parsers[17] = self.parseUDPHdr
        self.l4Parsers[1] = self.parseICMPHdr
    
    def __uh(self, val):
        return struct.unpack('>H', val)[0]

    
    def __uB(self, val):
        return struct.unpack('B', val)[0]

    
    def __uI(self, val):
        return struct.unpack('I', val)[0]

    
    def u6(self, val):
        return struct.unpack('BBB', val)[0]


    # Future : improve readability
    def parse(self, pkt):
        hds = []
        hds.append(self.parseEthHdr(pkt[0:14]))

        if hds[0].etherType == 0x800: # IPv4

            hds.append(self.parseIPv4Hdr(pkt[14:]))
            hlen = hds[1].hdrLen*4;

            if self.l4Parsers[hds[1].protocol] is not None:
                hds.append(self.l4Parsers[hds[1].protocol](pkt[(14+hlen):]))
            else:
                hds[1].payload = pkt[(14+hlen):]
                return hds

            
        elif hds[0].etherType == 0x86DD: # IPv6

            hds.append(self.parseIPv6Hdr(pkt[14:38]))
            if self.l4Parsers[hds[1].nextHdr] is not None:
                hds.append(self.l4Parsers[hds[1].nextHdr](pkt[44:]))
                # Future : adapt extnsion header
                # e.g. Routing header, Fragment header
            else:
                hds[1].payload = pkt[44:]
                return hds
        
        else:
            hds[0].payload = pkt[14:]
            return hds
        
    
        return hds

    
    def parseEthHdr(self, pkt):
        header = EthHdr()
        header.dstMac = binascii.hexlify(pkt[0:6]).decode()
        header.srcMac = binascii.hexlify(pkt[6:12]).decode()    
        header.etherType = self.__uh(pkt[12:14])
    
        return header

    
    def parseIPv4Hdr(self, pkt):
        header = IPv4Hdr()
        tmp = self.__uB(pkt[0:1])
        
        header.version = tmp >> 4
        header.hdrLen = tmp & 0b1111
        header.serviceType = self.__uB(pkt[1:2])
        header.totalLen = self.__uh(pkt[2:4])
        header.ident = self.__uh(pkt[4:6])
        
        tmp = self.__uh(pkt[6:8])
        header.flags = bin(tmp >> 12)
        header.flagmentOffset = tmp & 0b111111111111
        header.ttl = self.__uB(pkt[8:9])
        header.protocol = self.__uB(pkt[9:10])
        header.checksum = self.__uh(pkt[10:12])
        header.srcIP = socket.inet_ntoa(pkt[12:16])
        header.dstIP = socket.inet_ntoa(pkt[16:20])
        
        if header.hdrLen != 5:
            tmp = self.__uI(pkt[20:header.hdrLen*4])
            header.options = tmp >> 4
            header.padding = tmp & 0b1111
        
        return header                        

    def parseIPv6Hdr(self, pkt):
        header = IPv6Hdr()
        tmp = self.__uI(pkt[0:4])
        header.version = tmp >> (32-4)
        header.trafficClass = (tmp >> (32 - (4+8))) & 0b11111111
        header.flowLabel = tmp & 0b11111111111111111111
        header.payloadLen = self.__uh(pkt[4:6])
        header.nextHdr = self.__uB(pkt[6:7])
        #header.protocol = self.__uB(pkt[6:7])
        header.hopLim = self.__uB(pkt[7:8])
        header.srcIP = binascii.hexlify(pkt[8:24]).decode()
        header.dstIP = binascii.hexlify(pkt[24:40]).decode()
        if header.nextHdr == 43:
            pass
        
        return header
    
    def parseTCPHdr(self, pkt):
    
        header = TCPHdr()
    
        header.srcPort = self.__uh(pkt[0:2])
        header.dstPort = self.__uh(pkt[2:4])
        header.seqNumber = self.__uI(pkt[4:8])
        header.ackNumber = self.__uI(pkt[8:12])
        
        tmp = self.__uh(pkt[12:14])
        header.dataOffset = tmp >> 12
        header.reserved = (tmp >> 6) & 0b111111
        header.urg = (tmp >> 5) & 0b1
        header.ack = (tmp >> 4) & 0b1
        header.psh = (tmp >> 3) & 0b1
        header.rst = (tmp >> 2) & 0b1
        header.syn = (tmp >> 1) & 0b1 
        header.fin = tmp & 0b1 
        header.window = self.__uh(pkt[14:16])
        header.checksum = self.__uh(pkt[16:18])
        header.urgentPointer = self.__uh(pkt[18:20])
        
        
        dataPos = header.dataOffset*4
        if header.dataOffset > 5:
            header.options = pkt[20:dataPos]
            header.data = pkt[dataPos:]
            
        return header
        
    
    def parseUDPHdr(self, pkt):
        header = UDPHdr()
        header.srcPort = self.__uh(pkt[0:2])
        header.dstPort = self.__uh(pkt[2:4])
        header.length = self.__uh(pkt[4:6])
        header.checksum = self.__uh(pkt[6:8])
        header.data = pkt[8:]
        
        return header

    def parseICMPHdr(self, pkt):
        header = ICMPHdr()
        header.type = self.__uB(pkt[0:1])
        header.code = self.__uB(pkt[1:2])
        header.checksum = self.__uh(pkt[2:4])
        header.unused = self.__uI(pkt[4:8])
        header.InternetHdr = self.__uI(pkt[8:12])
        
        return header


    def parseDHCPHdr(self, pkt):
        header = DHCPHdr()
        header.op = uB(pkt[0:1])
        header.htype = uB(pkt[1:2])
        header.hlen = uB(pkt[2:3])
        header.hops = uB(pkt[3:4])
        header.xid = uI(pkt[4:8])
        header.secs = uh(pkt[8:10])
        header.flags = uh(pkt[10:12])
        header.ciaddr= inet_ntoa(pkt[12:16])
        header.yiaddr= inet_ntoa(pkt[16:20])
        header.siaddr= inet_ntoa(pkt[20:24])
        header.giaddr= inet_ntoa(pkt[24:28])
        header.chaddr = binascii.hexlify(pkt[28:44]).decode()
        header.sname = pkt[44:108]
        header.file = pkt[108:236]
        header.options = pkt[236:]

        return header
