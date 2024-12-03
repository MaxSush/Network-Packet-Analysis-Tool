import atexit
from flask import Blueprint, render_template, jsonify, request

from app.getpackets import GetPacket, get_interface

main = Blueprint('main', __name__)

obj = []
interfaces = get_interface() 
for i in interfaces:
    obj.append(GetPacket(interface=i))
interfaces.append("any")

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/data')
def data():
    results = []
    total_packets = 0
    for o in obj:
        packets = o.get_packets_sum()
        total_packets += packets
        results.append(packets)
        o.reset_result()
    results.append(total_packets)
    return jsonify({'interfaces': interfaces, 'value': results})

@main.route('/interface/<interface_name>', methods=['GET'])
def interface_page(interface_name):
    filters = request.args.get('filters', 'None')
    return f"Showing details for interface {interface_name} with filters: {filters}"

@main.route('/new')
def new():
    return render_template('new.html')

@atexit.register
def cleanup():
    for o in obj:
        o.stop()
        print(f"Stopping packet capture for {o.interface}...")