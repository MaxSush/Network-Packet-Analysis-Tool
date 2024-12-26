from scapy.all import sniff

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


class Pckt_Reader:
    def __init__(self, filename):
        self.filename = filename
        self.pkts = None
        self.__read(filename=filename)


    def get_pktset(self, set_no):
        total_packets = len(self.pkts)
        total_pages = (total_packets + 99) // 100
        print(f"Total packets: {total_packets}, Total pages: {total_pages}")
        if set_no < 1 or set_no > total_pages:
            return "invalid index no."
        start = (set_no - 1) * 100
        end = min(set_no * 100, total_packets)
        return self.get_packetinfo(start=start, end=end)

    def get_packetinfo(self, start, end):
        packets_list = []
        for i in range(start, end):
            p = self.pkts[i]
            packet_info = {
                "src": (getattr(p.payload, "src", p.src)),
                "dst": (getattr(p.payload, "dst", p.dst)),
                "proto": proto_dict.get(getattr(p, "proto", None), "N/A"),
                "length": (getattr(p, "len", len(p))),
                "summary": p.summary(),
            }
            packets_list.append(packet_info)
        return packets_list

    def __read(self, filename):
        try:
            self.pkts = sniff(offline=filename)
            print("successful")
        except Exception as e:
            print(f"Error reading packets: {e}")


if __name__ == "__main__":
    file = "/home/sushant/Python-Projects/website/Network-Packet-Analysis-Tool/app/tmp/hello.pcap"
    p = Pckt_Reader(file)
    l = p.get_pktset(1)
    print(l)
