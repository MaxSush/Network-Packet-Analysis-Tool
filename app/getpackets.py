from scapy.all import *
import threading
import time

def get_interface():
    interface = get_if_list()
    for i in interface:
        ipaddr = get_if_addr(i)
        if (ipaddr == '0.0.0.0'):
            interface.remove(i)
    return interface

class GetPacket:
    def __init__(self, interface):
        self.result = 0
        self.interface = interface
        self.running = True
        self.lock = threading.Lock()
        self.worker_thread = threading.Thread(target=self.__capture_packets)
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def stop(self):
        self.running = False
        if self.worker_thread.is_alive():
            self.worker_thread.join()

    def reset_result(self):
        self.result = 0

    def get_packets_sum(self):
        with self.lock:
            return self.result

    def is_alive(self):
        return self.worker_thread.is_alive()
    
    def process_packet(self, packet):
        with self.lock:
            self.result += 1

    def __capture_packets(self):
        while self.running:
            try:
                sniff(iface=self.interface, prn=self.process_packet, store=False, timeout=1)
            except PermissionError:
                print("PermissionError: [Errno 1] Operation not permitted. Run with sudo.")
                self.running = False
                break
            except OSError:
                print(f"Stoping packet sniffing for {self.interface}...")
                time.sleep(5)
            except Exception as e:
                print(f"Error capturing packets: {e}")
                time.sleep(5)


if __name__ == "__main__":
    interface_name = get_interface()[0][1]
    obj = GetPacket(interface_name)
    try:
        while True:
            results = obj.get_packets_sum()
            print(f"Packets captured in the last second: {results}")
            obj.reset_result()
            time.sleep(1)
    except KeyboardInterrupt:
        obj.stop()
        print("\nStopping packet capture...")
