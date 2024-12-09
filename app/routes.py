from pathlib import Path
import shutil
import signal
import threading
from urllib.parse import unquote
from flask import Blueprint, render_template, jsonify, request, send_file

from app.Utility.BPF_Syntax import list_to_bpf
from app.getpackets import GetPacket, get_interface
from app.interface import Interface_Packet

main = Blueprint("main", __name__)

pckt_obj: dict[str, GetPacket] = {}
iface_obj: dict[str, Interface_Packet] = {}
packet_list: list[dict] = []
tmp_dir = Path(__file__).resolve().parent / "tmp"
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
    filters = unquote(filters)
    filter_list = filters.split(",") if filters != "None" else []
    print(filter_list)
    bpf = str(list_to_bpf(filter_list))
    if interface_name not in iface_obj:
        for obj in iface_obj.values():
            print(f"Stopping filter packet capture for {obj.interface}...")
            print("Wait 20 sec...")
            obj.stop()
            print("Stopped")
        iface_obj.clear()
        print(f"Starting filter packet capture for {interface_name}...")
        iface_obj[interface_name] = Interface_Packet(bpf, interface_name)
    iface_obj[interface_name].control_running = True
    iface_obj[interface_name].filter = bpf
    iface_obj[interface_name].packets_list.clear()
    return render_template("interface.html", interface_name=interface_name, filters = bpf)


@main.route("/action/<interface_name>", methods=["POST"])
def handle_action(interface_name):
    data = request.json
    action = data.get("action")
    print(f"Received action: {action}")
    if action == "pause":
        iface_obj[interface_name].control_running = False
    if action == "play":
        iface_obj[interface_name].control_running = True
    if action == "refresh":
        iface_obj[interface_name].packets_list.clear
        packet_list.clear()        
    if action == "stop":
        print(f"Stopping filter packet capture for {interface_name}...")
        print("Estimated time 20 sec...")
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


@main.route("/download/<interface_name>", methods=["GET"])
def download_file(interface_name):
    if not tmp_dir.exists():
        return f"Temporary directory not found: {tmp_dir}", 404
    files = [f for f in tmp_dir.iterdir() if f.name.startswith(interface_name)]
    print([file.name for file in files])
    if not files:
        return f"No file found for interface: {interface_name}", 404
    latest_file = max(files, key=lambda f: f.stat().st_mtime)
    if latest_file.exists():
        return send_file(latest_file, as_attachment=True)
    else:
        return f"File not found: {latest_file}", 404


def cleanup():
    try:
        for obj in pckt_obj.values():
            print(f"Stopping packet capture for {obj.interface}...", flush=True)
            try:
                obj.stop()
                print(f"Stopped packet capture for {obj.interface}", flush=True)
            except Exception as e:
                print(
                    f"Error stopping packet capture for {obj.interface}: {e}",
                    flush=True,
                )
        pckt_obj.clear()
        for o in iface_obj.values():
            print(f"Stopping filter packet capture for {o.interface}...", flush=True)
            print("Estimated time 20 sec...")
            try:
                o.stop()
                print(f"Stopped filter packet capture for {o.interface}", flush=True)
            except Exception as e:
                print(
                    f"Error stopping filter packet capture for {o.interface}: {e}",
                    flush=True,
                )
            print("Stopped")
        iface_obj.clear()
        if tmp_dir.exists() and tmp_dir.is_dir():
            shutil.rmtree("app/tmp")
            print("Removed tmp directory")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def signal_handler(signum, frame):
    print(f"Signal {signum} received. Running cleanup...")
    print(f"Interrupt at line: {frame.f_lineno} in {frame.f_code.co_filename}")
    cleanup()
    print("Closing application ...")
    print("Active threads:", threading.enumerate())
    exit(0)


signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Handle termination
