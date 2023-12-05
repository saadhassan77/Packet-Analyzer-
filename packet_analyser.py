from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS
from datetime import datetime
import re  # Regex lib to match patterns in strings

# Initializing the Flask app
app = Flask(__name__, static_folder='static')

#app = Flask(__name__)

# Allowed interfaces
ALLOWED_INTERFACES = ['Wi-Fi', 'Ethernet', 'WiFi']
selected_interface = None

# Initializing flags 
captured_packets = []
capture_active = False

# Credentials patterns to detect
credential_keywords = {
    "username": re.compile(r"(?i)username|user|login"),
    "password": re.compile(r"(?i)password|pass|pwd"),
    "credit_card": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
}

def write_to_file(captured_packets):
    with open("captured_traffic.txt", "w") as file:
        for packet in captured_packets:
            file.write(f"Packet Number: {packet['Packet Number']}\n")
            file.write(f"Time: {packet['Time']}\n")
            file.write(f"Length: {packet['Length']}\n")
            file.write(f"Info: {packet['Info']}\n")
            file.write(f"Source IP: {packet['Source IP']}\n")
            file.write(f"Destination IP: {packet['Destination IP']}\n")
            file.write(f"Source Port: {packet['Source Port']}\n")
            file.write(f"Destination Port: {packet['Destination Port']}\n")
            file.write(f"Protocol: {packet['Protocol']}\n")
            file.write(f"Data: {packet['Data']}\n")
            file.write("==================================================================================\n")

        # Collect packets with detected credentials and their detailed information
        packets_with_credentials = [packet for packet in captured_packets if 'Detected Credentials' in packet and packet['Data']]
        if packets_with_credentials:
            file.write("\n\n\n==================================================================================\n")
            file.write("                              Detected Credentials:\n")
            file.write("==================================================================================\n")
            for packet in packets_with_credentials:
                file.write(f"Packet Number: {packet['Packet Number']}\n")
                file.write(f"Time: {packet['Time']}\n")
                file.write(f"Length: {packet['Length']}\n")
                file.write(f"Info: {packet['Info']}\n")
                file.write(f"Source IP: {packet['Source IP']}\n")
                file.write(f"Destination IP: {packet['Destination IP']}\n")
                file.write(f"Source Port: {packet['Source Port']}\n")
                file.write(f"Destination Port: {packet['Destination Port']}\n")
                file.write(f"Protocol: {packet['Protocol']}\n")
                file.write(f"Raw Data: {packet['Data']}\n")
                file.write("==============================================================================\n")

def check_for_credentials(payload):
    credentials_found = {}
    for key, pattern in credential_keywords.items():
        matches = pattern.finditer(payload)
        found_values = []
        for match in matches:
            found_values.append(match.group())
        if found_values:
            credentials_found[key] = found_values
    return credentials_found

def packet_callback(packet):
    if capture_active:
        packet_time = packet.time
        packet_time_formatted = datetime.fromtimestamp(packet_time).strftime('%Y-%m-%d %H:%M:%S')

        packet_count = len(captured_packets) + 1

        packet_length = len(packet)

        packet_details = {
            "Packet Number": packet_count,
            "Time": packet_time_formatted,
            "Length": packet_length,
            "Info": packet.summary(),
            "Source IP": None,
            "Destination IP": None,
            "Source Port": None,
            "Destination Port": None,
            "Protocol": "Unknown",
            "Data": ""
        }

        if IP in packet:
            packet_details["Source IP"] = packet[IP].src
            packet_details["Destination IP"] = packet[IP].dst

            if TCP in packet:
                packet_details["Protocol"] = "TCP"
                packet_details["Source Port"] = packet[TCP].sport
                packet_details["Destination Port"] = packet[TCP].dport

                if packet[TCP].dport in [80, 443]:
                    if Raw in packet:
                        load = packet.getlayer(Raw).load.decode(errors='ignore')
                        if load.startswith('GET') or load.startswith('POST'):
                            host = re.search(r"(?i)host:\s(.*?)\r\n", load)
                            packet_details["Data"] = load
                            packet_details["HTTP Request to"] = host.group(1)
                            
            elif UDP in packet:
                packet_details["Protocol"] = "UDP"
                packet_details["Source Port"] = packet[UDP].sport
                packet_details["Destination Port"] = packet[UDP].dport

                if packet[UDP].dport == 53:
                    if DNS in packet:
                        packet_details["Data"] = packet.getlayer(DNS).qd.qname.decode()

            # Check for credential keywords in the packet payload
            if Raw in packet:
                load = packet.getlayer(Raw).load.decode(errors='ignore')
                credentials = check_for_credentials(load)
                if credentials:
                    packet_details["Detected Credentials"] = credentials

        captured_packets.append(packet_details)
@app.route('/')
def index():
    return render_template('index6.html')

@app.route('/select_interface/<interface>')
def select_interface(interface):
    global selected_interface
    if interface in ALLOWED_INTERFACES:
        selected_interface = interface
        return jsonify({"success": True, "message": f"Interface selected: {interface}"})
    else:
        return jsonify({"success": False, "message": "Invalid interface"})

@app.route('/start_capture')
def start_capture():
    global capture_active, selected_interface
    capture_active = True
    if selected_interface:
        sniff(iface=selected_interface, prn=packet_callback, count=5000)
        return jsonify({"success": True, "message": f"Capture started on {selected_interface}."})
    else:
        return jsonify({"success": False, "message": "No interface selected"})

@app.route('/stop_capture')
def stop_capture():
    global capture_active
    capture_active = False
    write_to_file(captured_packets)

    return jsonify({"success": True, "message": "Capture stopped. Captured packets saved to captured_traffic.txt."})

@app.route('/clear_packets')
def clear_packets():
    global captured_packets
    captured_packets = []
    return jsonify({"success": True, "message": "Captured packets cleared."})

@app.route('/captured_packets')
def get_captured_packets():
    return jsonify(captured_packets)

if __name__ == '__main__':
    app.run(debug=True, port=3366)
