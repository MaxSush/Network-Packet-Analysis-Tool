from scapy.all import *
import threading
import time

proto_dict = {
    143: "Ethernet",
    121: "SMP",
    58: "IPv6-ICMP",
    51: "AH",
    41: "IPv6",
    27: "RDP",
    17: "UDP",
    6: "TCP",
    1: "ICMP",
    2: "IGMP",
}


class Interface_Packet:
    def __init__(self, filter, interface):
        self.running = True
        self.interface = interface
        self.packets_list = []
        self.lock = threading.Lock()
        self.worker_thread = threading.Thread(
            target=self.__capture_filter_packets, args=(filter, interface)
        )
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def process_filter(self, filter):
        print(filter)
        return filter

    def get_packets_list(self):
        with self.lock:
            return self.packets_list

    def process_pckt(self, pckt):
        with self.lock:
            packet_info = {
                "src": (getattr(pckt.payload, "src", pckt.src)),
                "dst": (getattr(pckt.payload, "dst", pckt.dst)),
                "proto": (getattr(pckt, "proto", "N/A")),
                "length": (getattr(pckt, "len", len(pckt))),
                "summary": pckt.summary(),
            }
            self.packets_list.append(packet_info)
            if len(self.packets_list) > 100:
                self.packets_list.pop(0)

            # wrpcap("tmp/temp.pcap", pckt, append=True)

    def __capture_filter_packets(self, filter, interface):
        def stop_sniffing(pckt):
            return not self.running
        while self.running:
            try:
                sniff(
                    iface=interface,
                    prn=self.process_pckt,
                    store=0,
                    timeout=20,
                    stop_filter=stop_sniffing,
                )
            except PermissionError:
                print("PermissionError: [Errno 1] Operation not permitted. Run with sudo.")
                self.running = False
            except Exception as e:
                print(f"Error capturing packets: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join()


if __name__ == "__main__":
    interface_name = "lo"
    filter = None
    obj = Interface_Packet(filter, interface_name)
    try:
        while True:
            results = obj.get_packets_list()
            print(f"Packets captured in the last second: {results}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        obj.stop()
        print("\nStopped packet capture...")
