#! /usr/bin/env python3


import socket
import struct
import fcntl
import ctypes

IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
ETH_P_ALL = 0x03


class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

    
class Capture(object):

    def __init__(self):

        self.__socket = None
        self.__interface = ''
        self.__promiscuous = False
        

    def setInterface(self, interface):
        self.__interface = interface

    def getInterface(self):
        return self.__interface


    def enablePromiscuous(self):
        self.__promiscuous = True

    def prepare(self):
        self.__socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.__socket.bind((self.__interface, ETH_P_ALL))

        ifr = ifreq()
        ifr.ifr_ifrn = self.__interface.encode()
        fcntl.ioctl(self.__socket.fileno(), SIOCGIFFLAGS, ifr)
        ifr.ifr_flags |= IFF_PROMISC
        fcntl.ioctl(self.__socket.fileno(), SIOCSIFFLAGS, ifr)
        

    def capture(self):
        
        pkt = self.__socket.recv(2048)
        if (len(pkt)<54):
            return None
        else:
            return pkt
