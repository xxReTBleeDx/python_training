import socket
import struct
import sys

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]  # Correction: assignation correcte du champ protocol_num
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]                                                                                                                                                     
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:                                                                                                                                                                                 self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:                                                                                                                                                               print('%s No protocol for %s' % (e, self.protocol_num))

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP  # Par défaut, capturer uniquement ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            ip_header = IP(raw_buffer[0:20])

            print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                              ip_header.src_address,
                                              ip_header.dst_address))

            # Modification: vérification explicite pour ne traiter que les paquets ICMP
            if ip_header.protocol == "ICMP":
                print(f'Version: {ip_header.ver}')
                print(f'Header Length: {ip_header.ihl}')
                print(f'TTL: {ip_header.ttl}')

                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                icmp_header = ICMP(buf)
                print('ICMP -> Type: %s Code: %s\n' % (icmp_header.type, icmp_header.code))

    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '0.0.0.0'  # Modification: écouter sur toutes les interfaces réseau

    sniff(host)
~