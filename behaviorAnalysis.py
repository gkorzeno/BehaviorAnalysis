#!/usr/bin/env python3
"""
Network-Based Behavior Analysis Engine
A hybrid IDS/ML system for detecting anomalous network behavior
"""

import os
import sys
import time
import json
import logging
import argparse
import sqlite3
import threading
import socket
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter

# For packet capture
try:
    import pyshark
except ImportError:
    print("Warning: pyshark not installed. Install with: pip install pyshark")
    print("Note: pyshark requires Wireshark/tshark to be installed on your system")

# For machine learning
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
except ImportError:
    print("Warning: scikit-learn not installed. Install with: pip install scikit-learn")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/netanalyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class NetworkBehaviorAnalyzer:
    def __init__(self, config):
        self.config = config
        self.running = True
        self.packet_queue = []
        self.queue_lock = threading.Lock()
        self.flow_data = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'start_time': None,
            'last_time': None,
            'protocols': Counter(),
            'tcp_flags': Counter(),
            'packet_sizes': [],
            'inter_arrival_times': []
        })
        
        # Create necessary directories
        os.makedirs(config['data_dir'], exist_ok=True)
        os.makedirs(config['models_dir'], exist_ok=True)
        
        # Initialize database
        self.init_database()
        
        # Load or train models
        self.load_models()
        
        # Load signature-based rules
        self.signatures = self.load_signatures()
        
        # Initialize baseline statistics
        self.baseline = self.load_baseline()
        
        # Track alerts to prevent duplicates
        self.recent_alerts = set()
    
    def init_database(self):
        """Initialize SQLite database for flow and alert storage"""
        db_path = os.path.join(self.config['data_dir'], 'netanalyzer.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create flows table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            packets INTEGER,
            bytes INTEGER,
            duration REAL,
            flags TEXT,
            avg_packet_size REAL,
            avg_inter_arrival REAL,
            is_anomalous INTEGER DEFAULT 0
        )
        ''')
        
        # Create alerts table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            alert_type TEXT,
            confidence REAL,
            message TEXT,
            flow_id INTEGER,
            FOREIGN KEY(flow_id) REFERENCES flows(id)
        )
        ''')
        
        self.conn.commit()
    
    def load_models(self):
        """Load or initialize machine learning models"""
        self.models = {}
        models_path = Path(self.config['models_dir'])
        
        # Try to load existing models
        for model_file in models_path.glob('*.pkl'):
            try:
                with open(model_file, 'rb') as f:
                    model_name = model_file.stem
                    self.models[model_name] = pickle.load(f)
                    logging.info(f"Loaded model: {model_name}")
            except Exception as e:
                logging.error(f"Error loading model {model_file}: {e}")
        
        # Initialize models if they don't exist
        if 'isolation_forest' not in self.models:
            self.models['isolation_forest'] = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )
            logging.info("Initialized new Isolation Forest model")
        
        if 'dbscan' not in self.models:
            self.models['dbscan'] = DBSCAN(
                eps=0.5,
                min_samples=5,
                n_jobs=-1
            )
            logging.info("Initialized new DBSCAN model")
        
        if 'random_forest' not in self.models and self.config.get('use_supervised', False):
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
            logging.info("Initialized new Random Forest model")
    
    def load_signatures(self):
        """Load signature-based detection rules"""
        signatures = []
        signatures_path = Path(self.config.get('signatures_file', 
                                              os.path.join(self.config['data_dir'], 'signatures.json')))
        
        if signatures_path.exists():
            try:
                with open(signatures_path, 'r') as f:
                    signatures = json.load(f)
                logging.info(f"Loaded {len(signatures)} signature rules")
            except Exception as e:
                logging.error(f"Error loading signatures: {e}")
        else:
            # Create default signatures
            signatures = [
                {
                    "name": "Port Scan",
                    "detection": {
                        "dst_ports_unique": {"min": 10},
                        "duration": {"max": 60},
                        "tcp_flags": {"contains": "S", "not_contains": "A"}
                    },
                    "severity": "high"
                },
                {
                    "name": "SYN Flood",
                    "detection": {
                        "protocol": "TCP",
                        "tcp_flags": {"equals": "S"},
                        "packets_per_second": {"min": 100}
                    },
                    "severity": "high"
                },
                {
                    "name": "DNS Tunneling",
                    "detection": {
                        "protocol": "DNS",
                        "avg_packet_size": {"min": 200},
                        "packets": {"min": 20}
                    },
                    "severity": "medium"
                }
            ]
            
            with open(signatures_path, 'w') as f:
                json.dump(signatures, f, indent=2)
            logging.info(f"Created default signatures file at {signatures_path}")
        
        return signatures
    
    def load_baseline(self):
        """Load or initialize baseline network statistics"""
        baseline_path = Path(os.path.join(self.config['data_dir'], 'baseline.json'))
        
        if baseline_path.exists():
            try:
                with open(baseline_path, 'r') as f:
                    baseline = json.load(f)
                logging.info("Loaded network baseline statistics")
                return baseline
            except Exception as e:
                logging.error(f"Error loading baseline: {e}")
        
        # Initialize empty baseline
        baseline = {
            'avg_flow_duration': 0,
            'avg_packets_per_flow': 0,
            'avg_bytes_per_flow': 0,
            'avg_packet_size': 0,
            'common_protocols': {},
            'common_ports': {},
            'flows_per_hour': {},
            'last_updated': datetime.now().isoformat()
        }
        
        return baseline
    
    def update_baseline(self):
        """Update baseline statistics from recent flow data"""
        logging.info("Updating network baseline statistics")
        
        try:
            # Get flow data from the last 24 hours
            one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
            self.cursor.execute('''
                SELECT 
                    protocol, dst_port, duration, packets, bytes, avg_packet_size,
                    strftime('%H', timestamp) as hour
                FROM flows
                WHERE timestamp > ? AND is_anomalous = 0
            ''', (one_day_ago,))
            
            flows = self.cursor.fetchall()
            
            if not flows:
                logging.warning("No recent normal flows found for baseline update")
                return
            
            # Process flow data
            protocols = Counter()
            ports = Counter()
            hours = Counter()
            durations = []
            packets_counts = []
            bytes_counts = []
            packet_sizes = []
            
            for flow in flows:
                protocol, dst_port, duration, packets, bytes_count, avg_pkt_size, hour = flow
                
                protocols[protocol] += 1
                ports[dst_port] += 1
                hours[hour] += 1
                
                if duration is not None:
                    durations.append(duration)
                if packets is not None:
                    packets_counts.append(packets)
                if bytes_count is not None:
                    bytes_counts.append(bytes_count)
                if avg_pkt_size is not None:
                    packet_sizes.append(avg_pkt_size)
            
            # Update baseline
            self.baseline['avg_flow_duration'] = np.mean(durations) if durations else 0
            self.baseline['avg_packets_per_flow'] = np.mean(packets_counts) if packets_counts else 0
            self.baseline['avg_bytes_per_flow'] = np.mean(bytes_counts) if bytes_counts else 0
            self.baseline['avg_packet_size'] = np.mean(packet_sizes) if packet_sizes else 0
            self.baseline['common_protocols'] = {k: v for k, v in protocols.most_common(10)}
            self.baseline['common_ports'] = {str(k): v for k, v in ports.most_common(20)}
            self.baseline['flows_per_hour'] = {str(k): v for k, v in hours.items()}
            self.baseline['last_updated'] = datetime.now().isoformat()
            
            # Save updated baseline
            baseline_path = os.path.join(self.config['data_dir'], 'baseline.json')
            with open(baseline_path, 'w') as f:
                json.dump(self.baseline, f, indent=2)
            
            logging.info("Baseline statistics updated successfully")
            
        except Exception as e:
            logging.error(f"Error updating baseline: {e}")
    
    def start_packet_capture(self):
        """Start capturing network packets"""
        interface = self.config.get('interface', None)
        bpf_filter = self.config.get('bpf_filter', None)
        
        logging.info(f"Starting packet capture on interface: {interface}")
        
        try:
            # Create capture object
            if interface:
                capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
            else:
                capture = pyshark.LiveCapture(bpf_filter=bpf_filter)
            
            # Process packets
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                
                try:
                    self.process_packet(packet)
                except Exception as e:
                    logging.error(f"Error processing packet: {e}")
        
        except Exception as e:
            logging.error(f"Error in packet capture: {e}")
            if "No such device" in str(e):
                logging.error(f"Interface '{interface}' not found. Available interfaces:")
                try:
                    available = pyshark.LiveCapture().get_interfaces()
                    for iface in available:
                        logging.error(f"  - {iface}")
                except:
                    pass
    
    def process_packet(self, packet):
        """Process a captured packet and add to flow data"""
        try:
            # Extract basic packet info
            timestamp = float(packet.sniff_timestamp)
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else packet.highest_layer
            
            # Get IP information
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            else:
                # Skip non-IP packets
                return
            
            # Get port information
            src_port = dst_port = 0
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                tcp_flags = packet.tcp.flags
            elif hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                tcp_flags = ""
            else:
                tcp_flags = ""
            
            # Get packet length
            try:
                packet_length = int(packet.length)
            except:
                packet_length = 0
            
            # Create flow keys (bidirectional)
            forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
            # Check if flow exists
            flow_key = None
            if forward_key in self.flow_data:
                flow_key = forward_key
            elif reverse_key in self.flow_data:
                flow_key = reverse_key
            else:
                # New flow
                flow_key = forward_key
                self.flow_data[flow_key]['start_time'] = timestamp
            
            # Update flow data
            flow = self.flow_data[flow_key]
            flow['packets'] += 1
            flow['bytes'] += packet_length
            flow['protocols'][protocol] += 1
            flow['packet_sizes'].append(packet_length)
            
            # Calculate inter-arrival time if not first packet
            if flow['last_time'] is not None:
                inter_arrival = timestamp - flow['last_time']
                flow['inter_arrival_times'].append(inter_arrival)
            
            flow['last_time'] = timestamp
            
            # Update TCP flags if present
            if tcp_flags:
                flow['tcp_flags'][tcp_flags] += 1
            
            # Check if flow is complete (idle for too long or has FIN/RST flags)
            current_time = time.time()
            flow_timeout = self.config.get('flow_timeout', 120)  # 2 minutes default
            
            # Process completed flows periodically
            if len(self.flow_data) > 1000 or (current_time - self.last_flow_check > 10):
                self.process_completed_flows()
                self.last_flow_check = current_time
        
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def process_completed_flows(self):
        """Process and store completed flows, then analyze them"""
        current_time = time.time()
        flow_timeout = self.config.get('flow_timeout', 120)
        completed_flows = []
        
        # Identify completed flows
        for flow_key, flow_data in list(self.flow_data.items()):
            # Check if flow is idle
            if flow_data['last_time'] is None:
                continue
                
            is_tcp = any('TCP' in p for p in flow_data['protocols'])
            has_fin_rst = any(flag in 'FR' for flags in flow_data['tcp_flags'] for flag in flags)
            is_idle = (current_time - flow_data['last_time']) > flow_timeout
            
            if (is_tcp and has_fin_rst) or is_idle:
                # Extract flow information
                src_ip, src_port, dst_info = flow_key.split('-', 2)
                dst_ip, dst_port = dst_info.split('-')[0].split(':')
                protocol = dst_info.split('-')[1] if len(dst_info.split('-')) > 1 else 'UNKNOWN'
                
                src_port = int(src_port)
                dst_port = int(dst_port)
                
                # Calculate flow statistics
                duration = flow_data['last_time'] - flow_data['start_time'] if flow_data['start_time'] else 0
                avg_packet_size = np.mean(flow_data['packet_sizes']) if flow_data['packet_sizes'] else 0
                avg_inter_arrival = np.mean(flow_data['inter_arrival_times']) if flow_data['inter_arrival_times'] else 0
                
                # Prepare flow record
                flow_record = {
                    'timestamp': datetime.fromtimestamp(flow_data['start_time']).isoformat() if flow_data['start_time'] else datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'packets': flow_data['packets'],
                    'bytes': flow_data['bytes'],
                    'duration': duration,
                    'flags': ','.join(flow_data['tcp_flags'].keys()),
                    'avg_packet_size': avg_packet_size,
                    'avg_inter_arrival': avg_inter_arrival,
                    'flow_key': flow_key
                }
                
                # Add to completed flows
                completed_flows.append(flow_record)
                
                # Remove from active flows
                del self.flow_data[flow_key]
        
        if completed_flows:
            # Store flows in database
            for flow in completed_flows:
                self.cursor.execute('''
                    INSERT INTO flows (
                        timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                        packets, bytes, duration, flags, avg_packet_size, avg_inter_arrival
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    flow['timestamp'], flow['src_ip'], flow['src_port'], 
                    flow['dst_ip'], flow['dst_port'], flow['protocol'],
                    flow['packets'], flow['bytes'], flow['duration'], 
                    flow['flags'], flow['avg_packet_size'], flow['avg_inter_arrival']
                ))
                
                # Get the flow ID
                flow_id = self.cursor.lastrowid
                flow['id'] = flow_id
            
            self.conn.commit()
            
            # Analyze flows for anomalies
            self.analyze_flows(completed_flows)
    
    def analyze_flows(self, flows):
        """Analyze flows for anomalies using signatures and ML models"""
        # First check signature-based rules
        for flow in flows:
            self.check_signatures(flow)
        
        # Prepare data for ML analysis
        if len(flows) >= 10:  # Only run ML on batches of sufficient size
            self.ml_analysis(flows)
    
    def check_signatures(self, flow):
        """Check if a flow matches any signature-based rules"""
        for signature in self.signatures:
            match = True
            detection_rules = signature.get('detection', {})
            
            for field, criteria in detection_rules.items():
                # Handle special fields
                if field == 'dst_ports_unique':
                    # This would require additional context from other flows
                    continue
                elif field == 'packets_per_second':
                    if flow['duration'] > 0:
                        pps = flow['packets'] / flow['duration']
                        if 'min' in criteria and pps < criteria['min']:
                            match = False
                            break
                        if 'max' in criteria and pps > criteria['max']:
                            match = False
                            break
                # Handle regular fields
                elif field in flow:
                    value = flow[field]
                    
                    if 'equals' in criteria and value != criteria['equals']:
                        match = False
                        break
                    if 'min' in criteria and value < criteria['min']:
                        match = False
                        break
                    if 'max' in criteria and value > criteria['max']:
                        match = False
                        break
                    if 'contains' in criteria and criteria['contains'] not in value:
                        match = False
                        break
                    if 'not_contains' in criteria and criteria['not_contains'] in value:
                        match = False
                        break
                else:
                    # Field not in flow, can't match
                    match = False
                    break
            
            if match:
                # Generate alert
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': flow['src_ip'],
                    'src_port': flow['src_port'],
                    'dst_ip': flow['dst_ip'],
                    'dst_port': flow['dst_port'],
                    'alert_type': f"signature:{signature['name']}",
                    'confidence': 1.0,  # High confidence for signature matches
                    'message': f"Signature match: {signature['name']} (Severity: {signature.get('severity', 'medium')})",
                    'flow_id': flow['id']
                }
                
                self.generate_alert(alert)
                
                # Mark flow as anomalous
                self.cursor.execute(
                    "UPDATE flows SET is_anomalous = 1 WHERE id = ?",
                    (flow['id'],)
                )
                self.conn.commit()
    
    def ml_analysis(self, flows):
        """Perform machine learning analysis on a batch of flows"""
        # Extract features for ML
        features = []
        flow_ids = []
        
        for flow in flows:
            # Skip flows already identified as anomalous by signatures
            if flow.get('is_anomalous'):
                continue
                
            # Basic features
            feature_vector = [
                flow['packets'],
                flow['bytes'],
                flow['duration'] if flow['duration'] else 0,
                flow['avg_packet_size'] if flow['avg_packet_size'] else 0,
                flow['avg_inter_arrival'] if flow['avg_inter_arrival'] else 0,
                1 if 'TCP' in flow['protocol'] else 0,
                1 if 'UDP' in flow['protocol'] else 0,
                1 if 'DNS' in flow['protocol'] else 0,
                1 if 'HTTP' in flow['protocol'] else 0,
                1 if 'HTTPS' in flow['protocol'] else 0,
                1 if flow['dst_port'] == 80 else 0,
                1 if flow['dst_port'] == 443 else 0,
                1 if flow['dst_port'] == 53 else 0,
                1 if flow['dst_port'] == 22 else 0,
                1 if flow['dst_port'] == 3389 else 0,
                1 if 'S' in flow['flags'] else 0,
                1 if 'F' in flow['flags'] else 0,
                1 if 'R' in flow['flags'] else 0,
                1 if 'P' in flow['flags'] else 0,
                1 if 'A' in flow['flags'] else 0
            ]
            
            features.append(feature_vector)
            flow_ids.append(flow['id'])
        
        if not features:
            return
        
        # Convert to numpy array
        X = np.array(features)
        
        # Normalize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Run anomaly detection with Isolation Forest
        if 'isolation_forest' in self.models:
            try:
                # Predict anomalies
                y_pred = self.models['isolation_forest'].fit_predict(X_scaled)
                scores = self.models['isolation_forest'].decision_function(X_scaled)
                
                # Process results
                for i, (pred, score) in enumerate(zip(y_pred, scores)):
                    if pred == -1:  # Anomaly
                        flow_id = flow_ids[i]
                        flow = next((f for f in flows if f['id'] == flow_id), None)
                        
                        if flow:
                            # Generate alert
                            alert = {
                                'timestamp': datetime.now().isoformat(),
                                'src_ip': flow['src_ip'],
                                'src_port': flow['src_port'],
                                'dst_ip': flow['dst_ip'],
                                'dst_port': flow['dst_port'],
                                'alert_type': "ml:isolation_forest",
                                'confidence': min(1.0, abs(score) * 0.2),  # Scale score to confidence
                                'message': f"Anomalous flow detected by Isolation Forest (score: {score:.2f})",
                                'flow_id': flow_id
                            }
                            
                            self.generate_alert(alert)
                            
                            # Mark flow as anomalous
                            self.cursor.execute(
                                "UPDATE flows SET is_anomalous = 1 WHERE id = ?",
                                (flow_id,)
                            )
                
                # Save updated model
                model_path = os.path.join(self.config['models_dir'], 'isolation_forest.pkl')
                with open(model_path, 'wb') as f:
                    pickle.dump(self.models['isolation_forest'], f)
            
            except Exception as e:
                logging.error(f"Error in Isolation Forest analysis: {e}")
        
        # Run clustering with DBSCAN
        if 'dbscan' in self.models:
            try:
                # Fit DBSCAN
                cluster_labels = self.models['dbscan'].fit_predict(X_scaled)
                
                # Find outliers (label -1)
                for i, label in enumerate(cluster_labels):
                    if label == -1:  # Outlier
                        flow_id = flow_ids[i]
                        flow = next((f for f in flows if f['id'] == flow_id), None)
                        
                        if flow:
                            # Generate alert
                            alert = {
                                'timestamp': datetime.now().isoformat(),
                                'src_ip': flow['src_ip'],
                                'src_port': flow['src_port'],
                                'dst_ip': flow['dst_ip'],
                                'dst_port': flow['dst_port'],
                                'alert_type': "ml:dbscan",
                                'confidence': 0.7,  # Fixed confidence for DBSCAN
                                'message': f"Outlier flow detected by DBSCAN clustering",
                                'flow_id': flow_id
                            }
                            
                            self.generate_alert(alert)
                            
                            # Mark flow as anomalous
                            self.cursor.execute(
                                "UPDATE flows SET is_anomalous = 1 WHERE id = ?",
                                (flow_id,)
                            )
            
            except Exception as e:
                logging.error(f"Error in DBSCAN analysis: {e}")
        
        self.conn.commit()
    
    def generate_alert(self, alert):
        """Generate and store an alert"""
        # Create a unique key for the alert to prevent duplicates
        alert_key = f"{alert['src_ip']}:{alert['dst_ip']}:{alert['alert_type']}"
        
        # Check if we've recently generated this alert
        current_time = time.time()
        alert_cooldown = self.config.get('alert_cooldown', 300)  # 5 minutes default
        
        for recent_key, timestamp in list(self.recent_alerts):
            if current_time - timestamp > alert_cooldown:
                self.recent_alerts.remove((recent_key, timestamp))
        
        # Skip if this alert was recently generated
        if any(key == alert_key for key, _ in self.recent_alerts):
            return
        
        # Add to recent alerts
        self.recent_alerts.add((alert_key, current_time))
        
        # Log the alert
        logging.warning(f"ALERT: {alert['message']} - {alert['src_ip']}:{alert['src_port']} -> {alert['dst_ip']}:{alert['dst_port']}")
        
        # Store in database
        self.cursor.execute('''
            INSERT INTO alerts (
                timestamp, src_ip, src_port, dst_ip, dst_port,
                alert_type, confidence, message, flow_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'], alert['src_ip'], alert['src_port'],
            alert['dst_ip'], alert['dst_port'], alert['alert_type'],
            alert['confidence'], alert['message'], alert['flow_id']
        ))
        
        self.conn.commit()
        
        # Execute response actions if configured
        self.execute_response(alert)
    
    def execute_response(self, alert):
        """Execute automated response actions based on alert type and severity"""
        # Check if responses are enabled
        if not self.config.get('enable_responses', False):
            return
        
        # Get response configuration
        responses = self.config.get('responses', {})
        
        # Determine response based on alert type and confidence
        alert_type = alert['alert_type']
        confidence = alert['confidence']
        
        # Check for matching response
        for response_config in responses:
            if 'alert_type' in response_config and response_config['alert_type'] not in alert_type:
                continue
                
            if 'min_confidence' in response_config and confidence < response_config['min_confidence']:
                continue
            
            # Execute action
            action = response_config.get('action')
            if action == 'block_ip':
                src_ip = alert['src_ip']
                logging.info(f"Executing response: Blocking IP {src_ip}")
                
                # Example: Add IP to iptables
                if self.config.get('simulate_responses', True):
                    logging.info(f"SIMULATION: Would run: iptables -A INPUT -s {src_ip} -j DROP")
                else:
                    try:
                        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
                    except Exception as e:
                        logging.error(f"Error executing iptables command: {e}")
            
            elif action == 'custom_command':
                command = response_config.get('command', '').format(
                    src_ip=alert['src_ip'],
                    dst_ip=alert['dst_ip'],
                    src_port=alert['src_port'],
                    dst_port=alert['dst_port']
                )
                
                logging.info(f"Executing response: Custom command")
                
                if self.config.get('simulate_responses', True):
                    logging.info(f"SIMULATION: Would run: {command}")
                else:
                    try:
                        os.system(command)
                    except Exception as e:
                        logging.error(f"Error executing custom command: {e}")

    def execute_response(self, alert):
        """Execute automated response actions based on alert type and severity"""
        if not self.config.get('enable_responses', False):
            return
        
        responses = self.config.get('responses', [])
        alert_type = alert['alert_type']
        confidence = alert['confidence']
        
        for response_config in responses:
            if 'alert_type' in response_config and response_config['alert_type'] not in alert_type:
                continue
            if 'min_confidence' in response_config and confidence < response_config['min_confidence']:
                continue
            
            action = response_config.get('action')
            if action == 'block_ip':
                src_ip = alert['src_ip']
                logging.info(f"Executing response: Blocking IP {src_ip}")
                if self.config.get('simulate_responses', True):
                    logging.info(f"SIMULATION: iptables -A INPUT -s {src_ip} -j DROP")
                else:
                    os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            
            elif action == 'custom_command':
                command = response_config.get('command', '').format(
                    src_ip=alert['src_ip'],
                    dst_ip=alert['dst_ip'],
                    alert_type=alert_type
                )
                logging.info(f"Executing custom command: {command}")
                if not self.config.get('simulate_responses', True):
                    os.system(command)

    def stop(self):
        """Stop the analyzer and clean up"""
        logging.info("Stopping Network Behavior Analyzer...")
        self.running = False
        if hasattr(self, 'conn'):
            self.conn.close()

    def main():
        parser = argparse.ArgumentParser(description='Network Behavior Analysis Engine')
        parser.add_argument('--interface', type=str, help='Network interface to monitor')
        parser.add_argument('--data-dir', type=str, default='./data', help='Directory for DB and logs')
        parser.add_argument('--models-dir', type=str, default='./models', help='Directory for ML models')
        parser.add_argument('--simulate', action='store_true', default=True, help='Simulate responses (dont run iptables)')
        
        args = parser.parse_args()

        # Configuration Dictionary
        config = {
            'interface': args.interface,
            'data_dir': args.data_dir,
            'models_dir': args.models_dir,
            'flow_timeout': 60,
            'alert_cooldown': 300,
            'enable_responses': True,
            'simulate_responses': args.simulate,
            'use_supervised': False,
            'responses': [
                {
                    'alert_type': 'signature:Port Scan',
                    'action': 'block_ip',
                    'min_confidence': 0.9
                }
            ]
        }

        analyzer = NetworkBehaviorAnalyzer(config)
        analyzer.last_flow_check = time.time()

        # Start capture in a separate thread
        capture_thread = threading.Thread(target=analyzer.start_packet_capture)
        capture_thread.daemon = True
        capture_thread.start()

        logging.info("Engine is running. Press Ctrl+C to stop.")

        try:
            while True:
                # Periodic tasks: Baseline updates every hour
                analyzer.update_baseline()
                # Check for completed flows every 10 seconds if not handled by packet processing
                analyzer.process_completed_flows()
                time.sleep(10)
        except KeyboardInterrupt:
            analyzer.stop()
            sys.exit(0)

if __name__ == "__main__":
    main()
