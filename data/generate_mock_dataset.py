import csv
import random
from datetime import datetime, timedelta

def generate_dataset(file_path="data/CICIDS2017_sample.csv", num_records=10000):
    headers = [
        "Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port",
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets", 
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", 
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", 
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", 
        "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Max", "Flow IAT Min", 
        "Fwd IAT Total", "Bwd IAT Total", "Fwd Header Length", "Bwd Header Length", 
        "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max", 
        "Packet Length Mean", "Packet Length Std", "SYN Flag Count", "RST Flag Count", 
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "Average Packet Size", 
        "Init_Win_bytes_forward", "Init_Win_bytes_backward", "min_seg_size_forward", 
        "Active Mean", "Idle Mean", "Label"
    ]

    base_time = datetime.now() - timedelta(days=1)
    
    # Attack and Benign definitions
    attack_types = ["BENIGN", "DDoS", "Port Scan", "Brute Force", "Botnet"]
    
    with open(file_path, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for i in range(num_records):
            # Pick a timestamp
            timestamp = (base_time + timedelta(seconds=i * random.uniform(0.5, 2.0))).strftime("%Y-%m-%d %H:%M:%S")
            
            # Decide label distribution: 60% Benign, 20% DDoS, 10% Port Scan, 6% Brute Force, 4% Botnet
            rand = random.random()
            if rand < 0.60:
                label = "BENIGN"
            elif rand < 0.80:
                label = "DDoS"
            elif rand < 0.90:
                label = "Port Scan"
            elif rand < 0.96:
                label = "Brute Force"
            else:
                label = "Botnet"
                
            # Default values
            src_ip = f"192.168.1.{random.randint(2, 254)}"
            dst_ip = f"192.168.1.{random.randint(2, 254)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 8080, 22, 21, 3389])
            
            flow_duration = random.randint(1000, 10000000)
            total_fwd_pkts = random.randint(1, 100)
            total_bwd_pkts = random.randint(0, 100)
            total_fwd_len = total_fwd_pkts * random.randint(40, 1000)
            total_bwd_len = total_bwd_pkts * random.randint(40, 1000)
            
            fwd_len_max = random.randint(40, 1500)
            fwd_len_min = random.randint(0, 40)
            fwd_len_mean = (fwd_len_max + fwd_len_min) / 2
            
            bwd_len_max = random.randint(40, 1500)
            bwd_len_min = random.randint(0, 40)
            bwd_len_mean = (bwd_len_max + bwd_len_min) / 2
            
            syn_flags = random.randint(0, 1)
            rst_flags = random.randint(0, 1)
            psh_flags = random.randint(0, 1)
            ack_flags = random.randint(0, 1)
            urg_flags = 0
            
            init_win_fwd = random.randint(1000, 65535)
            init_win_bwd = random.randint(0, 65535)
            min_seg_fwd = random.choice([20, 32, 40])
            
            active_mean = random.randint(0, 100000)
            idle_mean = random.randint(0, 1000000)
            
            # Customize parameters based on label to create highly distinguishable signatures
            if label == "BENIGN":
                # Standard HTTP/HTTPS or internal traffic
                dst_port = random.choice([80, 443, 8080])
                flow_duration = random.randint(50000, 5000000)
                total_fwd_pkts = random.randint(5, 30)
                total_bwd_pkts = random.randint(5, 30)
                total_fwd_len = total_fwd_pkts * random.randint(60, 1000)
                total_bwd_len = total_bwd_pkts * random.randint(100, 1500)
                
                fwd_len_max = random.randint(500, 1460)
                fwd_len_min = 0
                fwd_len_mean = random.randint(100, 500)
                
                bwd_len_max = random.randint(1000, 1460)
                bwd_len_min = 0
                bwd_len_mean = random.randint(200, 800)
                
                syn_flags = 1
                rst_flags = 0
                psh_flags = random.choice([0, 1])
                ack_flags = 1
                
                init_win_fwd = 29200
                init_win_bwd = 28960
                
            elif label == "DDoS":
                # High traffic volume, short duration, single target destination, spoofed sources
                src_ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                dst_ip = "192.168.1.100"  # Target server
                dst_port = random.choice([80, 443])
                flow_duration = random.randint(500, 15000)  # Very short flow duration
                total_fwd_pkts = random.randint(150, 800)   # High packet rate
                total_bwd_pkts = random.randint(0, 5)        # Minimal server response (overwhelmed)
                
                total_fwd_len = total_fwd_pkts * random.choice([40, 64])  # Small, uniform packet length
                total_bwd_len = total_bwd_pkts * 0
                
                fwd_len_max = 64
                fwd_len_min = 40
                fwd_len_mean = 50
                bwd_len_max = 0
                bwd_len_min = 0
                bwd_len_mean = 0
                
                syn_flags = 1  # SYN Flood
                rst_flags = 0
                psh_flags = 0
                ack_flags = 0
                
                init_win_fwd = 512
                init_win_bwd = 0
                
            elif label == "Port Scan":
                # Scanner probing sequential ports with quick, tiny connection attempts
                dst_ip = "192.168.1.100"
                # Select sequential ports based on index to simulate scanning
                dst_port = (i % 1000) + 1  
                flow_duration = random.randint(10, 800)  # Extremely short
                total_fwd_pkts = random.choice([1, 2])
                total_bwd_pkts = random.choice([0, 1])
                
                total_fwd_len = total_fwd_pkts * 40
                total_bwd_len = total_bwd_pkts * 40
                
                fwd_len_max = 40
                fwd_len_min = 40
                fwd_len_mean = 40
                bwd_len_max = 40
                bwd_len_min = 0
                bwd_len_mean = 20
                
                syn_flags = 1
                rst_flags = random.choice([0, 1])
                psh_flags = 0
                ack_flags = 0
                
                init_win_fwd = 1024
                init_win_bwd = 0
                
            elif label == "Brute Force":
                # High frequency SSH/RDP/FTP authentication attempts from a single source
                src_ip = "192.168.1.215"
                dst_ip = "192.168.1.100"
                dst_port = random.choice([22, 21, 3389]) # SSH, FTP, RDP
                flow_duration = random.randint(10000, 300000)
                total_fwd_pkts = random.randint(30, 120)
                total_bwd_pkts = random.randint(25, 110)
                
                total_fwd_len = total_fwd_pkts * random.randint(50, 120)
                total_bwd_len = total_bwd_pkts * random.randint(60, 150)
                
                fwd_len_max = 256
                fwd_len_min = 40
                fwd_len_mean = 85
                bwd_len_max = 512
                bwd_len_min = 40
                bwd_len_mean = 110
                
                syn_flags = 1
                rst_flags = 0
                psh_flags = 1
                ack_flags = 1
                
                init_win_fwd = 65535
                init_win_bwd = 65535
                
            elif label == "Botnet":
                # Compromised internal host beaconing/connecting to suspicious external IP
                src_ip = "192.168.1.55"
                dst_ip = f"{random.choice([45, 91, 104, 185])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                dst_port = random.choice([6667, 8080, 9001]) # IRC, HTTP, Tor ports
                flow_duration = random.randint(5000000, 60000000) # Long duration (session keep-alive)
                total_fwd_pkts = random.randint(15, 60)
                total_bwd_pkts = random.randint(15, 60)
                
                total_fwd_len = total_fwd_pkts * random.randint(40, 100)
                total_bwd_len = total_bwd_pkts * random.randint(40, 100)
                
                fwd_len_max = 100
                fwd_len_min = 40
                fwd_len_mean = 60
                bwd_len_max = 100
                bwd_len_min = 40
                bwd_len_mean = 60
                
                syn_flags = 1
                rst_flags = 0
                psh_flags = random.choice([0, 1])
                ack_flags = 1
                
                active_mean = random.randint(5000, 30000)
                idle_mean = random.randint(2000000, 10000000) # Significant idle time between beacons
                
            # Derived network fields (flow rates)
            duration_sec = max(1e-6, flow_duration / 1000000.0) # convert microsec to sec
            flow_bytes_sec = (total_fwd_len + total_bwd_len) / duration_sec
            flow_pkts_sec = (total_fwd_pkts + total_bwd_pkts) / duration_sec
            
            fwd_pkts_sec = total_fwd_pkts / duration_sec
            bwd_pkts_sec = total_bwd_pkts / duration_sec
            
            flow_iat_mean = flow_duration / max(1, (total_fwd_pkts + total_bwd_pkts - 1))
            flow_iat_max = flow_duration * 0.8
            flow_iat_min = flow_duration * 0.05
            
            fwd_iat_total = flow_duration * 0.95
            bwd_iat_total = flow_duration * 0.90 if total_bwd_pkts > 0 else 0
            
            fwd_hdr_len = total_fwd_pkts * min_seg_fwd
            bwd_hdr_len = total_bwd_pkts * 32
            
            pkt_len_min = min(fwd_len_min, bwd_len_min if total_bwd_pkts > 0 else fwd_len_min)
            pkt_len_max = max(fwd_len_max, bwd_len_max if total_bwd_pkts > 0 else fwd_len_max)
            pkt_len_mean = (total_fwd_len + total_bwd_len) / max(1, total_fwd_pkts + total_bwd_pkts)
            pkt_len_std = (pkt_len_max - pkt_len_min) / 4.0
            
            avg_pkt_size = pkt_len_mean
            
            # Compile row
            row = [
                timestamp, src_ip, src_port, dst_ip, dst_port,
                flow_duration, total_fwd_pkts, total_bwd_pkts,
                total_fwd_len, total_bwd_len,
                fwd_len_max, fwd_len_min, round(fwd_len_mean, 2),
                bwd_len_max, bwd_len_min, round(bwd_len_mean, 2),
                round(flow_bytes_sec, 2), round(flow_pkts_sec, 2), round(flow_iat_mean, 2), round(flow_iat_max, 2), round(flow_iat_min, 2),
                round(fwd_iat_total, 2), round(bwd_iat_total, 2), fwd_hdr_len, bwd_hdr_len,
                round(fwd_pkts_sec, 2), round(bwd_pkts_sec, 2), pkt_len_min, pkt_len_max,
                round(pkt_len_mean, 2), round(pkt_len_std, 2), syn_flags, rst_flags,
                psh_flags, ack_flags, urg_flags, round(avg_pkt_size, 2),
                init_win_fwd, init_win_bwd, min_seg_fwd,
                active_mean, idle_mean, label
            ]
            
            writer.writerow(row)
            
    print(f"Generated synthetic dataset containing {num_records} records successfully at: {file_path}")

if __name__ == "__main__":
    generate_dataset()
