import atexit
from flask import Blueprint, render_template, jsonify, request

from app.getpackets import GetPacket, get_interface
from app.interface import Interface_Packet

main = Blueprint("main", __name__)


pckt_obj: dict[str, GetPacket] = {}
iface_obj: dict[str, Interface_Packet] = {}
packet_list: list[dict] = []

interfaces = get_interface()


@main.route("/")
def index():
    if not pckt_obj:
        for i in interfaces:
            print(f"Starting packet capture for {i}...")
            pckt_obj[i] = GetPacket(i)
        interfaces.append("any")
    return render_template("index.html")


@main.route("/data")
def data():
    results = []
    total_packets = 0
    for o in pckt_obj.values():
        packets = o.get_packets_sum()
        total_packets += packets
        results.append(packets)
        o.reset_result()
    results.append(total_packets)
    return jsonify({"interfaces": interfaces, "value": results})


@main.route("/interface/<interface_name>", methods=["GET"])
def interface_page(interface_name):
    filters = request.args.get("filters", "None")
    if interface_name not in iface_obj:
        for obj in iface_obj.values():
            print(f"Stopping filter packet capture for {obj.interface}...")
            print("Wait 20 sec...")
            obj.stop()
            print("Stopped")
        iface_obj.clear()
        print(f"Starting filter packet capture for {interface_name}...")
        iface_obj[interface_name] = Interface_Packet(filters, interface_name)
    iface_obj[interface_name].packets_list.clear()
    return render_template("interface.html", interface_name=interface_name)


@main.route("/action/<interface_name>", methods=["POST"])
def handle_action(interface_name):
    data = request.json
    action = data.get("action")
    print(f"Received action: {action}")
    if action == "pause":
        iface_obj[interface_name].control_running = False
    if action == "play":
        iface_obj[interface_name].control_running = True
    if action == "download":
        print("download")
    if action == "stop":
        print(f"Stopping filter packet capture for {o.interface}...")
        print("Wait 20 sec...")
        iface_obj[interface_name].stop()
        iface_obj.clear()
        print("Stopped")
    return jsonify({"status": "success", "action": action})


@main.route("/packets/<interface_name>")
def get_packets(interface_name):
    global packet_list
    if interface_name in iface_obj:
        packet_list = iface_obj[interface_name].get_packets_list()
    return jsonify(packet_list)


@atexit.register
def cleanup():
    for o in pckt_obj.values():
        o.stop()
        print(f"Stopping packet capture for {o.interface}...")
    pckt_obj.clear()
    for o in iface_obj.values():
        print(f"Stopping filter packet capture for {o.interface}...")
        print("Wait 20 sec...")
        o.stop()
        print("Stopped")
    iface_obj.clear()
