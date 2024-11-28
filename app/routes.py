import atexit
from flask import Blueprint, render_template, jsonify

from app.getpackets import GetPacket, get_interface

main = Blueprint('main', __name__)

obj = []
interfaces = get_interface() 
print(interfaces)
for i in interfaces:
    obj.append(GetPacket(interface=i))

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/data')
def data():
    results = []
    for o in obj:
        results.append(o.get_packets_sum())
        o.reset_result()
    return jsonify({'interfaces': interfaces, 'value': results})

@atexit.register
def cleanup():
    for o in obj:
        o.stop()
        print(f"Stopping packet capture for {o.interface}...")