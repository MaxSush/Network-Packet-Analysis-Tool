from scapy.all import *

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


def storepackets(pckt):
    wrpcap("temp.pcap", pckt)


a = sniff(iface="lo", timeout=1, prn=storepackets, store=True)

pkts = rdpcap("temp.pcap")
print(pkts[0].json())
print(proto_dict[pkts[0].payload.proto])
