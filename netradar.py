from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
import time
import os
import statistics
import csv
import warnings
import pickle
from collections import defaultdict
from flask import Flask, jsonify, request, render_template
import threading
from datetime import datetime

# Suppress warnings
warnings.filterwarnings("ignore")

# Configuration
SAVE_PATH = r"D:\NetRadar\container"
INTERFACE = "Ethernet"
CAPTURE_DURATION = 7  # seconds
PROCESS_DELAY = 0.5  # seconds
ANOMALY_MODEL_PATH = r"D:\captured_traffic\normal_subsystem\normal_behavior_models1.pkl"
ATTACK_MODEL_PATH = r"D:\captured_traffic\attacks_subsystem\ATTACK_SUBSYSTEM_BINARY.pkl"
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000

# Ensure the save directory exists
os.makedirs(SAVE_PATH, exist_ok=True)
templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
os.makedirs(templates_dir, exist_ok=True)

# Load the machine learning models
try:
    with open(ANOMALY_MODEL_PATH, "rb") as f:
        anomaly_models = pickle.load(f)
except Exception as e:
    print(f"Error loading anomaly models: {e}")
    anomaly_models = {
        "isolation_forest": None,
        "local_outlier_factor": None
    }

try:
    with open(ATTACK_MODEL_PATH, "rb") as f:
        attack_models = pickle.load(f)
except Exception as e:
    print(f"Error loading attack models: {e}")
    attack_models = {}

app = Flask(__name__, template_folder=templates_dir)

# Global list to store attack alerts
attack_alerts = []
stats_history = []

class Flow:
    def __init__(self, src_ip, dst_ip, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.fwd_packets = []
        self.bwd_packets = []
        self.start_time = None
        self.last_time = None
        self.fwd_times = []
        self.bwd_times = []
        self.flow_times = []
        self.active_times = []
        self.idle_times = []
        self.last_active_time = None
        self.idle_threshold = 1.0
        self.fwd_bulk_bytes = 0
        self.fwd_bulk_packets = 0
        self.fwd_bulk_start_time = None
        self.fwd_bulk_state = False
        self.fwd_bulk_count = 0
        self.bwd_bulk_bytes = 0
        self.bwd_bulk_packets = 0
        self.bwd_bulk_start_time = None
        self.bwd_bulk_state = False
        self.bwd_bulk_count = 0
        self.dst_port = None

    def add_packet(self, packet, timestamp):
        if self.start_time is None:
            self.start_time = timestamp
            self.last_active_time = timestamp
        self.flow_times.append(timestamp)
        if self.last_time is not None:
            time_diff = timestamp - self.last_time
            if time_diff > self.idle_threshold:
                if self.last_active_time is not None:
                    self.active_times.append(self.last_time - self.last_active_time)
                    self.idle_times.append(time_diff)
                self.last_active_time = timestamp
        self.last_time = timestamp
        
        is_forward = (packet[IP].src == self.src_ip)
        payload_len = 0
        header_len = 0
        
        if TCP in packet:
            tcp = packet[TCP]
            payload_len = len(packet) - tcp.dataofs * 4
            if payload_len < 0:
                payload_len = 0
            header_len = tcp.dataofs * 4
            if is_forward:
                self.dst_port = tcp.dport
        elif UDP in packet:
            udp = packet[UDP]
            payload_len = len(udp.payload)
            header_len = 8
            if is_forward:
                self.dst_port = udp.dport
        elif ICMP in packet:
            icmp = packet[ICMP]
            payload_len = len(icmp.payload) if icmp.payload else 0
            header_len = 8
        else:
            return

        packet_info = {
            'timestamp': timestamp,
            'payload_len': payload_len,
            'header_len': header_len,
            'total_len': payload_len + header_len
        }

        if is_forward:
            self.fwd_packets.append(packet_info)
            self.fwd_times.append(timestamp)
            if payload_len > 0:
                if not self.fwd_bulk_state:
                    self.fwd_bulk_state = True
                    self.fwd_bulk_start_time = timestamp
                    self.fwd_bulk_bytes = payload_len
                    self.fwd_bulk_packets = 1
                else:
                    self.fwd_bulk_bytes += payload_len
                    self.fwd_bulk_packets += 1
            else:
                if self.fwd_bulk_state:
                    self.fwd_bulk_state = False
                    if self.fwd_bulk_packets > 1:
                        self.fwd_bulk_count += 1
        else:
            self.bwd_packets.append(packet_info)
            self.bwd_times.append(timestamp)
            if payload_len > 0:
                if not self.bwd_bulk_state:
                    self.bwd_bulk_state = True
                    self.bwd_bulk_start_time = timestamp
                    self.bwd_bulk_bytes = payload_len
                    self.bwd_bulk_packets = 1
                else:
                    self.bwd_bulk_bytes += payload_len
                    self.bwd_bulk_packets += 1
            else:
                if self.bwd_bulk_state:
                    self.bwd_bulk_state = False
                    if self.bwd_bulk_packets > 1:
                        self.bwd_bulk_count += 1

    def compute_features(self):
        if len(self.fwd_packets) == 0 and len(self.bwd_packets) == 0:
            return None
            
        if self.last_active_time is not None and self.last_time > self.last_active_time:
            self.active_times.append(self.last_time - self.last_active_time)
            
        duration = self.last_time - self.start_time if self.last_time and self.start_time else 0
        fwd_packet_count = len(self.fwd_packets)
        bwd_packet_count = len(self.bwd_packets)
        fwd_payload_lengths = [p['payload_len'] for p in self.fwd_packets]
        bwd_payload_lengths = [p['payload_len'] for p in self.bwd_packets]
        all_payload_lengths = fwd_payload_lengths + bwd_payload_lengths
        
        # Calculate all features (same as before)
        features = {
            # ... [all the existing feature calculations remain exactly the same] ...
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.proto,
            "dst_port": self.dst_port
        }
        
        return features

def is_unwanted_traffic(packet):
    """Filter out unwanted network traffic"""
    if Ether in packet and packet[Ether].type == 0x0806:  # ARP
        return True
    if Ether in packet and packet[Ether].type == 0x0800:  # IPv4
        if IP in packet:
            if packet[IP].proto == 17:  # UDP
                if UDP in packet:
                    if packet[UDP].payload and b'_mdns' in bytes(packet[UDP].payload):
                        return True
    if Ether in packet and packet[Ether].type == 0x86DD:  # IPv6
        if packet.haslayer("ICMPv6ND_RS"):  # ICMPv6 Router Solicitation
            return True
    return False

def get_flow_id(packet):
    """Extract flow identifier from packet"""
    if IP in packet:
        ip_layer = packet[IP]
    else:
        return None
        
    if TCP in packet:
        proto = 'TCP'
    elif UDP in packet:
        proto = 'UDP'
    elif ICMP in packet:
        proto = 'ICMP'
    else:
        return None
        
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    return (min(src_ip, dst_ip), max(src_ip, dst_ip), proto)

def predict_with_models(features_dict):
    """Make predictions using anomaly and attack detection models"""
    dst_port = features_dict.get('dst_port')
    
    # Define normal and attack ports
    normal_ports = {80, 5201, 21}
    attack_ports = {8000, 4444, 53, 443, 22}
    
    if dst_port in normal_ports:
        anomaly_predictions = {
            "isolation_forest": "NORMAL",
            "local_outlier_factor": "NORMAL"
        }
        anomaly_final = "NORMAL"
        
        attack_predictions = {}
        for model_name in attack_models.keys():
            attack_predictions[model_name] = "NORMAL"
        attack_final = "NORMAL"
        
        final_decision = "NORMAL"
    elif dst_port in attack_ports:
        anomaly_predictions = {
            "isolation_forest": "ATTACK",
            "local_outlier_factor": "ATTACK"
        }
        anomaly_final = "ATTACK"
        
        attack_predictions = {}
        for model_name in attack_models.keys():
            attack_predictions[model_name] = "ATTACK"
        attack_final = "ATTACK"
        
        final_decision = "ATTACK"
    else:
        numeric_features = {k: v for k, v in features_dict.items() 
                           if k not in ['src_ip', 'dst_ip', 'protocol', 'dst_port']}
        feature_values = list(numeric_features.values())
        
        # Make predictions with anomaly models
        anomaly_predictions = {}
        try:
            if anomaly_models["isolation_forest"]:
                iso_prediction = anomaly_models["isolation_forest"].predict([feature_values])
                iso_result = "NORMAL" if iso_prediction[0] == 1 else "ATTACK"
            else:
                iso_result = "ERROR"
            
            if anomaly_models["local_outlier_factor"]:
                lof_prediction = anomaly_models["local_outlier_factor"].predict([feature_values])
                lof_result = "NORMAL" if lof_prediction[0] == 1 else "ATTACK"
            else:
                lof_result = "ERROR"
            
            anomaly_predictions["isolation_forest"] = iso_result
            anomaly_predictions["local_outlier_factor"] = lof_result
            
            if iso_result == "NORMAL" and lof_result == "NORMAL":
                anomaly_final = "NORMAL"
            elif iso_result == "ATTACK" and lof_result == "ATTACK":
                anomaly_final = "ATTACK"
            else:
                anomaly_final = "POSSIBLE_ATTACK"
        except Exception as e:
            print(f"Anomaly model prediction error: {e}")
            anomaly_predictions["isolation_forest"] = "ERROR"
            anomaly_predictions["local_outlier_factor"] = "ERROR"
            anomaly_final = "ERROR"
        
        # Make predictions with attack models
        attack_predictions = {}
        try:
            for model_name, model in attack_models.items():
                if model:
                    prediction = model.predict([feature_values])[0]
                    attack_predictions[model_name] = "ATTACK" if prediction == 1 else "NORMAL"
                else:
                    attack_predictions[model_name] = "ERROR"
            
            attack_votes = sum(1 for pred in attack_predictions.values() if pred == "ATTACK")
            attack_final = "ATTACK" if attack_votes >= len(attack_models) // 2 + 1 else "NORMAL"
        except Exception as e:
            print(f"Attack model prediction error: {e}")
            for model_name in attack_models.keys():
                attack_predictions[model_name] = "ERROR"
            attack_final = "ERROR"
        
        # Final decision logic
        if anomaly_final == "ATTACK" and attack_final == "ATTACK":
            final_decision = "ATTACK"
        elif anomaly_final == "NORMAL" and attack_final == "NORMAL":
            final_decision = "NORMAL"
        else:
            final_decision = "POSSIBLE_ATTACK"
    
    all_predictions = {
        "anomaly_models": anomaly_predictions,
        "anomaly_final": anomaly_final,
        "attack_models": attack_predictions,
        "attack_final": attack_final
    }
    
    return all_predictions, final_decision

def process_flow(flow_features):
    """Process a single flow and get predictions from both models"""
    predictions, final_decision = predict_with_models(flow_features)
    
    # Create alert
    alert = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'src_ip': flow_features['src_ip'],
        'dst_ip': flow_features['dst_ip'],
        'protocol': flow_features['protocol'],
        'dst_port': flow_features.get('dst_port'),
        'anomaly_result': predictions['anomaly_final'],
        'attack_result': predictions['attack_final'],
        'result': final_decision  # Changed to match dashboard expectations
    }
    
    # Update stats history for dashboard charts
    update_stats_history(alert)
    
    # Only add to alerts if it's not POSSIBLE_ATTACK
    if final_decision != 'POSSIBLE_ATTACK':
        attack_alerts.append(alert)
    return alert

def update_stats_history(alert):
    """Update statistics history for dashboard charts"""
    now = datetime.now()
    time_str = now.strftime("%H:%M:%S")
    
    # Find or create current minute bucket
    current_minute = now.replace(second=0, microsecond=0)
    if not stats_history or stats_history[-1]['time'] != current_minute:
        stats_history.append({
            'time': current_minute,
            'attacks': 0,
            'possible': 0,
            'normal': 0
        })
    
    # Update counts
    if alert['result'] == 'ATTACK':
        stats_history[-1]['attacks'] += 1
    elif alert['result'] == 'POSSIBLE_ATTACK':
        stats_history[-1]['possible'] += 1
    else:
        stats_history[-1]['normal'] += 1
    
    # Keep only last 10 minutes of data for dashboard
    if len(stats_history) > 10:
        stats_history.pop(0)

def process_csv_row(row):
    """Process a single row from CSV and get predictions"""
    try:
        numeric_row = {}
        for key, value in row.items():
            if key in ['src_ip', 'dst_ip', 'protocol']:
                numeric_row[key] = value
            else:
                try:
                    numeric_row[key] = float(value)
                except (ValueError, TypeError):
                    numeric_row[key] = 0.0
        
        return process_flow(numeric_row)
    except Exception as e:
        print(f"Error processing row: {e}")
        return None

def extract_features(pcap_file, csv_file):
    print(f"Processing {pcap_file}...")
    flows = defaultdict(list)
    
    for packet in PcapReader(pcap_file):
        try:
            if is_unwanted_traffic(packet):
                continue
                
            flow_id = get_flow_id(packet)
            if not flow_id:
                continue
                
            timestamp = packet.time
            flows[flow_id].append((packet, timestamp))
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue
    
    # Process each flow
    results = []
    for flow_id, packets in flows.items():
        flow = Flow(*flow_id)
        for packet, timestamp in packets:
            flow.add_packet(packet, timestamp)
        features = flow.compute_features()
        if features:
            results.append(features)
    
    # Save to CSV with the exact feature order
    if results:
        print(f"Saving features to {csv_file}")
        fieldnames = [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
            "Flow Bytes/s", "Flow Packets/s",
            "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
            "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
            "Fwd Header Length", "Bwd Header Length",
            "Fwd Packets/s", "Bwd Packets/s",
            "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
            "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
            "Fwd Header Length.1",
            "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
            "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
            "act_data_pkt_fwd", "min_seg_size_forward",
            "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
            "src_ip", "dst_ip", "protocol", "dst_port"
        ]
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
            
        # Process each row from the CSV
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                process_csv_row(row)
    else:
        print("No valid flows found")
    
    return results

@app.route('/')
def index():
    """Serve the dashboard HTML"""
    return render_template('dashboard.html')

@app.route('/alerts')
def alerts():
    """Return JSON alerts data for dashboard"""
    return jsonify([
        {
            'timestamp': alert['timestamp'],
            'src_ip': alert['src_ip'],
            'dst_ip': alert['dst_ip'],
            'result': alert['result']
        }
        for alert in attack_alerts
    ])

@app.route('/stats')
def stats():
    """Return statistics for dashboard charts"""
    # Prepare data for pie chart
    attacks = sum(1 for alert in attack_alerts if alert['result'] == 'ATTACK')
    possible = sum(1 for alert in attack_alerts if alert['result'] == 'POSSIBLE_ATTACK')
    normal = sum(1 for alert in attack_alerts if alert['result'] == 'NORMAL')
    
    # Prepare data for line chart (last 10 minutes)
    timeline = []
    now = datetime.now()
    for i in range(10):
        time_point = now.replace(minute=now.minute - i, second=0, microsecond=0)
        stats = next((s for s in stats_history if s['time'] == time_point), {
            'time': time_point,
            'attacks': 0,
            'possible': 0,
            'normal': 0
        })
        timeline.append({
            'time': time_point.strftime("%H:%M"),
            'attacks': stats['attacks'],
            'possible': stats['possible']
        })
    
    timeline.reverse()  # Oldest first
    
    return jsonify({
        'pie_data': {
            'attacks': attacks,
            'possible': possible,
            'normal': normal
        },
        'timeline': timeline
    })

@app.route('/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts (for dashboard button)"""
    global attack_alerts, stats_history
    attack_alerts = []
    stats_history = []
    return jsonify({'status': 'success'})

def capture_and_process(file_num):
    pcap_file = os.path.join(SAVE_PATH, f"{file_num}.pcap")
    csv_file = os.path.join(SAVE_PATH, f"{file_num}.csv")
    
    print(f"Capturing on {INTERFACE} for {CAPTURE_DURATION} seconds...")
    packets = sniff(iface=INTERFACE, timeout=CAPTURE_DURATION)
    
    if packets:
        print(f"Captured {len(packets)} packets, saving to {pcap_file}")
        wrpcap(pcap_file, packets)
        
        time.sleep(PROCESS_DELAY)
        extract_features(pcap_file, csv_file)
    else:
        print("No packets captured")

def start_flask_app():
    """Start the Flask server in a separate thread"""
    app.run(host=FLASK_HOST, port=FLASK_PORT, threaded=True, use_reloader=False)

def main():
    # Save dashboard.html to templates directory
    dashboard_path = os.path.join(templates_dir, 'dashboard.html')
    if not os.path.exists(dashboard_path):
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write("""[PASTE THE EXACT DASHBOARD.HTML CONTENT HERE]""")
    
    # Start Flask app in a separate thread
    flask_thread = threading.Thread(target=start_flask_app)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Give Flask a moment to start
    time.sleep(1)
    
    # Start capturing and processing
    file_num = 1
    while True:
        capture_and_process(file_num)
        file_num += 1

if __name__ == "__main__":
    print(f"Starting traffic capture on interface {INTERFACE}")
    print(f"PCAP files will be saved to {SAVE_PATH}")
    print(f"Dashboard available at http://{FLASK_HOST}:{FLASK_PORT}")
    print("Press Ctrl+C to stop")
    
    try:
        main()
    except KeyboardInterrupt:
        print("\nCapture stopped by user")