<div align="center">

<img src="https://img.shields.io/badge/NetShield-AI--Driven%20Network%20IDS-blue?style=for-the-badge&logo=shield&logoColor=white" alt="NetShield Banner">

# NetShield

### Intelligent AI-Driven Network Intrusion Detection System & Incident Analyzer

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.0+-61DAFB?style=flat-square&logo=react&logoColor=white)](https://reactjs.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-Random%20Forest-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Gemini](https://img.shields.io/badge/AI-Gemini%201.5%20Flash-4285F4?style=flat-square&logo=google-gemini&logoColor=white)](https://aistudio.google.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Stream live network traffic parameters, classify cyber threats using machine learning, and automatically generate comprehensive security reports and SIGMA detection rules using Google Gemini AI.**

</div>

---

## 📖 What is NetShield?

NetShield is a fully integrated, containerized Network Intrusion Detection System (NIDS) designed to identify and analyze cyber attacks in real-time. It bridges the gap between raw machine learning classification and human-readable threat intelligence:

1. **Ingest & Extract**: Collects network flow records containing packet-level metrics (packet size, flow duration, flags).
2. **Classify**: Applies a trained Random Forest model to instantly categorize traffic as Benign or one of 4 major attack types.
3. **Reason with AI**: Routes positive attack signatures through the Gemini API to explain the threat context, tactics, and risks.
4. **Generate Rules**: Auto-creates production-ready SIGMA rules and maps attacks to the MITRE ATT&CK framework.
5. **Visualize**: Renders real-time security alerts, statistics graphs, and collapsible intelligence panels in a modern glassmorphic dashboard.

---

## 🚀 Key Features

| Feature | Details |
|---|---|
| **Real-time Classifier** | Scans 38 traffic parameters (e.g. flow duration, pack rates, TCP flags) with a validation accuracy $\ge$ 98.4%. |
| **Generative Threat Summaries** | Uses Google Gemini 1.5 Flash to automatically compose readable threat logs describing target vectors. |
| **SIGMA Rule Generation** | Auto-generates standard YAML SIGMA filters to help security teams import blocks directly to SIEMs (Splunk, ELK). |
| **MITRE ATT&CK Mapping** | Maps classified threats to MITRE Tactics (e.g., Command and Control, Impact) and Techniques (T1498, T1110). |
| **Live Simulator Controller** | Streams synthetic traffic flows based on the CICIDS2017 schema to demonstrate active alert responses. |
| **Glassmorphic Cyber Dashboard** | Stunning dark space themed React user interface with Recharts telemetry visualizations. |
| **DevOps Containerization** | Instantly launch the entire environment (React, FastAPI, PostgreSQL) using a single Docker Compose script. |

---

## 🏗️ System Architecture

```
                       [ Network Traffic Source / Simulator ]
                                         │
                                         ▼
                           [ FastAPI /api/analyze Endpoint ]
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
    [ ML Classifier Model ]                             [ SQLAlchemy Store ]
      (Random Forest Model)                                      │
   (Predicts Threat & Confidence)                                │
                 │                                               ▼
                 ▼                                     [ PostgreSQL Database ]
       [ Gemini AI Engine ]                                 (Store Alerts)
     (MITRE ATT&CK & SIGMA)                                      │
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         ▼
                             [ REST / WebSocket APIs ]
                                         │
                                         ▼
                           [ React + Vite Web Dashboard ]
                         (Stats, Pie/Bar Charts, Log Tables)
```

---

## ⚡ Quick Start

Follow these steps to run the NetShield stack on your local machine:

### Prerequisites
*   [Docker Desktop](https://www.docker.com/products/docker-desktop/)
*   Gemini API Key (Get a free one from [Google AI Studio](https://aistudio.google.com/apikey))

### 1. Clone & Set Environment
Create a copy of this repository on your computer and navigate to the root directory:
```bash
git clone https://github.com/your-username/NetShield.git
cd NetShield
```

Create a `.env` file in the root directory by copying the example environment file:
```bash
cp .env.example .env
```
Open `.env` in a text editor and paste your Gemini API key:
```env
GEMINI_API_KEY=AIzaSyYourRealKeyHere
```
*(If no key is configured, the application falls back gracefully to template threat intelligence reports, so it remains fully functional).*

### 2. Launch with Docker Compose
Start the PostgreSQL database, FastAPI server, and Vite React client:
```bash
docker compose up --build -d
```
Once the build completes and the containers are healthy, open your web browser and navigate to:
*   **Web Dashboard**: `http://localhost:5173`
*   **FastAPI API Swagger Docs**: `http://localhost:8000/docs`

---

## 🛡️ Detection Modules

NetShield classifies traffic flows into five distinct categories based on network signature attributes:

1. **BENIGN (Normal Baseline)**: Standard web traffic (HTTP/S), exhibiting balanced forward/backward packets and typical duration parameters.
2. **DDoS (Distributed Denial of Service)**: Floods of small, uniform inbound packets (e.g., TCP SYN flood) from spoofed sources targeting destination ports 80/443.
3. **Port Scan**: Rapid connection attempts targeting sequential destination ports with minimal packet lengths, attempting to profile host vulnerabilities.
4. **Brute Force**: High-frequency ssh, ftp, or rdp authentication attempts originating from a single host source.
5. **Botnet**: Persistent, low-volume communication (beacons) on non-standard ports, exhibiting large idle times between contact intervals.

---

## 📂 Project Structure

```
NetShield/
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   │   └── engine.py        # Gemini AI prompt integration & SIGMA generator
│   │   ├── ml/
│   │   │   ├── model.py         # Inference model loading and classification wrapper
│   │   │   └── train.py         # Sklearn model training script
│   │   ├── simulator/
│   │   │   └── live_feed.py     # Background simulator thread
│   │   ├── store/
│   │   │   └── alert_store.py   # Database initialization and CRUD sessions
│   │   ├── __init__.py
│   │   └── routes.py            # API routes (health, alerts, stats, simulate)
│   ├── models/
│   │   ├── ids_model.pkl        # Saved Random Forest classifier model
│   │   └── label_encoder.pkl    # Saved scikit-learn LabelEncoder
│   ├── Dockerfile
│   ├── main.py                  # FastAPI entry point
│   └── requirements.txt         # Backend Python packages
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AlertFeed.jsx    # Live list and detailed inspector view
│   │   │   ├── AttackChart.jsx  # Recharts Doughnut and Bar charts
│   │   │   ├── Header.jsx       # Branding, stats indicator, and controls
│   │   │   └── StatsCards.jsx   # Metrics telemetry panels
│   │   ├── App.css
│   │   ├── App.jsx              # Coordinator and API polling loop
│   │   ├── index.css            # Dark mode glassmorphic styling
│   │   └── main.jsx
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
├── data/
│   ├── generate_mock_dataset.py # Mock dataset generation script
│   └── CICIDS2017_sample.csv    # Generated synthetic network logs
├── docker-compose.yml           # Container orchestrator config
├── .env.example                 # Example variables file
└── README.md                    # Project documentation
```

---

## 🔬 Tech Stack Selection

| Technology | Role | Why It Was Chosen |
|---|---|---|
| **FastAPI** | REST API Backend | Lightweight, asynchronous, auto-generates interactive Swagger documentation, and has clean integration with Python ML tools. |
| **React + Vite** | User Interface | Highly responsive UI, lightning-fast HMR during development, and easy state syncing for real-time polling. |
| **PostgreSQL** | Storage | Robust ACID compliance and index structures, serving as the standard database choice in enterprise SOC environments. |
| **Scikit-Learn** | Machine Learning | Tabular network flow records are highly structured and are best classified using decision-tree ensembles like Random Forest rather than deep learning. |
| **Google Gemini API** | AI Threat Intel | Fast response speeds, excellent reasoning capability, and clean structured markdown rule output. |

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
