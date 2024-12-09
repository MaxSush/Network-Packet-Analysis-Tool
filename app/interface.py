from scapy.all import *
import threading
import time
import os

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
        self.control_running = True
        self.interface = interface
        self.filter = filter
        self.packets_list = []
        os.makedirs("app/tmp", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"{interface}_{timestamp}.pcap"
        self.file_path = os.path.join("app/tmp", file_name)
        print(self.file_path)
        self.lock = threading.Lock()
        self.worker_thread = threading.Thread(
            target=self.__capture_filter_packets, args=(self.interface,)
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
                "proto": proto_dict.get(getattr(pckt, "proto", None), "N/A"),
                "length": (getattr(pckt, "len", len(pckt))),
                "summary": pckt.summary(),
            }
            self.packets_list.append(packet_info)
            if len(self.packets_list) > 100:
                self.packets_list.pop(0)

            wrpcap(self.file_path, pckt, append=True)

    def __capture_filter_packets(self, interface):
        def stop_sniffing(pckt):
            return not self.control_running

        while self.running:
            try:
                if self.control_running:
                    print(f"Using filter: {self.filter}")
                    print(f"Interface: {interface}")
                    sniff(
                        filter=self.filter,
                        iface=interface,
                        prn=self.process_pckt,
                        store=0,
                        timeout=20,
                        stop_filter=stop_sniffing,
                    )
                else:
                    time.sleep(4)
            except PermissionError:
                print(
                    "PermissionError: [Errno 1] Operation not permitted. Run with sudo."
                )
                self.running = False
            except Exception as e:
                print(f"Error capturing packets: {e}")
                time.sleep(10)

    def stop(self):
        self.running = False
        self.control_running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=20)
            time.sleep(1)


if __name__ == "__main__":
    interface_name = "lo"
    filter = ""
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
        print("Active threads:", threading.enumerate())
