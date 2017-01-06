from pycap.capture import Capture
from pycap.parse import Parser

import sys


def main(interface):

    cap = Capture()
    
    cap.setInterface(interface)
    #cap.enablePromiscuous()

    cap.prepare()
    
    parser = Parser()
    
    for i in range(1, 50):
        d = cap.capture()

        if d is not None:
            data = parser.parse(d)
            if len(data) > 1:
                if data[0].etherType == 0x800: # IPv4
                    print('srcIP : {0}'.format(data[1].srcIP))
                    print('dstIP : {0}'.format(data[1].dstIP))

                    if data[1].protocol == 6 or data[1].protocol == 17: # TCP or UDP
                        print('srcPort : {0}'.format(data[2].srcPort))
                        print('dstPort : {0}'.format(data[2].dstPort))
                    elif data[1].protocol == 1:
                        print('ICMP Type: {}'.format(data[2].type))
                        print('ICMP Code: {}'.format(data[2].code))
            print()
                
            
if __name__ == '__main__':
    argv = sys.argv
    if len(argv) == 2:
        main(argv[1])
    else:
        print('sudo python {} <interface>'.format(argv[0]))
