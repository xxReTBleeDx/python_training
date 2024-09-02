from scapy.all import sniff

def callback(packet):
    print(packet.show())

def main():
    sniff(prn=callback, count=1)

if __name__=='__main__':
    main()
