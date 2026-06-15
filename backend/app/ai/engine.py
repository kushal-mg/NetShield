import os
import google.generativeai as genai

# Setup Gemini API key
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

# Fallback templates for when API key is missing or call fails
MOCK_REPORTS = {
    "DDoS": """### 🛡️ Threat Intelligence Report: Distributed Denial of Service (DDoS)

#### 1. Executive Summary
A high-volume distributed denial-of-service (DDoS) traffic flow was detected targeting a core service. The signature exhibits an elevated rate of inbound forward packets (SYN/UDP flood style) with minimal return flow, indicating a deliberate attempt to exhaust server resources, exhaust connection queues, and degrade service availability.

#### 2. MITRE ATT&CK Mapping
*   **Tactic**: Impact (TA0040)
*   **Technique**: Network Denial of Service (T1498)
*   **Sub-technique**: Direct Network Flood (T1498.001)

#### 3. SIGMA Detection Rule
```yaml
title: High Volume Network Inbound Flood (DDoS)
id: 5a8a92bf-d2f1-4c6e-b3f7-45920a4bde7d
status: experimental
description: Detects traffic volume spikes typical of DDoS floods.
logsource:
    category: firewall
detection:
    selection:
        total_fwd_packets: '> 100'
        flow_duration: '< 5000'
    condition: selection
falsepositives:
    - High-throughput backup processes
    - Large media content streaming sessions
level: high
```""",

    "Port Scan": """### 🛡️ Threat Intelligence Report: Network Port Reconnaissance (Port Scan)

#### 1. Executive Summary
Sequential port probing attempts were detected originating from a single source host. The connections are extremely brief with little to no payload, consistent with automated network scanning utilities (e.g., Nmap). The threat actor is trying to map open ports and discover active network services to identify potential vulnerabilities for exploitation.

#### 2. MITRE ATT&CK Mapping
*   **Tactic**: Reconnaissance (TA0043)
*   **Technique**: Active Scanning (T1595)
*   **Sub-technique**: IP Addresses / Port Scanning (T1595.001)

#### 3. SIGMA Detection Rule
```yaml
title: Rapid Sequential Port Scan Detection
id: 8d2b9d5c-3f2a-431e-b83c-1bda82348509
status: production
description: Detects host mapping via sequential network port scanning.
logsource:
    category: network_flow
detection:
    selection:
        flow_duration: '< 1000'
        total_fwd_packets: 1
    condition: selection
falsepositives:
    - Internal network monitoring/inventory tools
    - Vulnerability scanners authorized by administration
level: medium
```""",

    "Brute Force": """### 🛡️ Threat Intelligence Report: Authentication Brute Force Attack

#### 1. Executive Summary
An elevated frequency of authentication attempts was detected targeting common management ports (such as SSH, RDP, or FTP). The bidirectional packet statistics show multiple short connections from a single host, representing credential stuffing or dictionary attack profiles designed to gain unauthorized access to server consoles.

#### 2. MITRE ATT&CK Mapping
*   **Tactic**: Credential Access (TA0006)
*   **Technique**: Brute Force (T1110)
*   **Sub-technique**: Password Guessing (T1110.001)

#### 3. SIGMA Detection Rule
```yaml
title: Repeated Authentication Connection Failures (Brute Force)
id: f1e2d3c4-b5a6-7890-c1d2-e3f4a5b6c7d8
status: production
description: Detects repeated authentication flow patterns targeting administration ports.
logsource:
    category: authentication
detection:
    selection:
        dst_port:
            - 22
            - 3389
            - 21
        total_fwd_packets: '> 30'
    condition: selection
falsepositives:
    - Misconfigured administrative script or automation cron
    - Users forgetting their credentials
level: high
```""",

    "Botnet": """### 🛡️ Threat Intelligence Report: Botnet Beaconing & C2 Communication

#### 1. Executive Summary
An internal host exhibited long-lived, periodic connection handshakes to an external address on non-standard control channels. The traffic pattern shows steady packet sizes and consistent idle intervals, indicating malicious beaconing behavior related to a Botnet Command and Control (C2) agent checking in for remote instructions.

#### 2. MITRE ATT&CK Mapping
*   **Tactic**: Command and Control (TA0011)
*   **Technique**: Web Service / Non-Standard Port (T1043)
*   **Sub-technique**: Protocol Tunneling (T1572)

#### 3. SIGMA Detection Rule
```yaml
title: Botnet Command and Control (C2) Beaconing
id: a7b8c9d0-e1f2-3a4b-5c6d-7e8f9a0b1c2d
status: experimental
description: Detects outbound communication patterns related to botnet commands.
logsource:
    category: network_flow
detection:
    selection:
        flow_duration: '> 5000000'
        idle_mean: '> 2000000'
    condition: selection
falsepositives:
    - Legitimate telemetry loops or background cloud backups
    - Real-time stock tickers or chat protocols
level: critical
```""",

    "BENIGN": """### 🛡️ Threat Intelligence Report: Normal Network Baseline (BENIGN)

#### 1. Executive Summary
The analyzed traffic conforms to the normal baseline parameters of network activity. Connections display balanced forward and backward packet structures, standard protocol ports (such as HTTPS), and standard segment dimensions. No anomaly signature is present.

#### 2. MITRE ATT&CK Mapping
No TTP mapping required. Traffic matches standard business baseline.

#### 3. SIGMA Detection Rule
Not applicable. No detection signature required for normal baseline traffic.
"""
}

def generate_threat_summary(attack_type, confidence, severity, features):
    # Formulate key features for the prompt
    features_summary = {
        "Destination Port": features.get("Destination Port"),
        "Flow Duration": features.get("Flow Duration"),
        "Total Fwd Packets": features.get("Total Fwd Packets"),
        "Total Backward Packets": features.get("Total Backward Packets"),
        "Flow Packets/s": features.get("Flow Packets/s"),
        "Flow Bytes/s": features.get("Flow Bytes/s")
    }
    
    # If no API key, return mock template matching attack type
    if not api_key:
        return MOCK_REPORTS.get(attack_type, MOCK_REPORTS["BENIGN"])
        
    prompt = f"""
You are a senior cybersecurity incident responder and threat intelligence analyst.
Review this Network Intrusion Detection System (NIDS) alert:
- Attack Type: {attack_type}
- ML Model Confidence: {confidence * 100:.2f}%
- Designated Severity: {severity}
- Selected Traffic Parameters: {features_summary}

Please generate a structured threat analysis report containing:
1. Executive Summary: A concise narrative explanation of what this attack means, what the threat actor is trying to achieve, and the technical impact on the network.
2. MITRE ATT&CK Mapping: List the Tactics, Techniques, and Procedures (TTPs) related to this attack (with ID and name).
3. SIGMA Detection Rule: A standard SIGMA rule in YAML block format to detect this attack in network logs. Use standard fields (title, logsource, detection, condition, falsepositives, level).

Respond ONLY in clean Markdown format. Do not add conversational intro/outro. Use emoji icons and headings.
"""

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini API call failed: {e}. Falling back to default threat template.")
        return MOCK_REPORTS.get(attack_type, MOCK_REPORTS["BENIGN"])
