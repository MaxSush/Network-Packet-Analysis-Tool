def list_to_bpf(filter_list):
    if not filter_list:
        return ""

    bpf_parts = []
    host = None
    port = None

    for filter in filter_list:
        filter = filter.strip().lower()

        if filter in ["tcp", "udp", "icmp", "arp"]: 
            bpf_parts.append(filter)
        elif filter.startswith("host "):  
            host = filter
        elif filter.startswith("port "): 
            port = filter
        else:
            bpf_parts.append(filter)  

    if host and port:
        bpf_parts.append(f"{host} and {port}")
    elif host:
        bpf_parts.append(host)
    elif port:
        bpf_parts.append(port)

    if len(bpf_parts) == 1:
        return bpf_parts[0]
    else:
        return " or ".join(bpf_parts)


if __name__ == "__main__":
    filter_list = ["tcp", "host 192.168.1.10", "port 80"]
    bpf = list_to_bpf(filter_list=filter_list)
    print(bpf)
