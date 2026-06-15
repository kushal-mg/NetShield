# NetShield: AI-Driven Network Intrusion Detection System (IDS)

We will build the **NetShield** application stack in the workspace directory `d:\projects\NetShield`. 

NetShield is a modern, AI-driven Network Intrusion Detection System (IDS) designed for a BTech portfolio. It showcases:
1. **Network Flow Classification**: An ML model (Random Forest) trained to identify benign traffic and 4 major attack vectors (DDoS, Port Scan, Brute Force, Botnet) using features styled after the CICIDS2017 dataset.
2. **AI Threat Intelligence**: Integration with the Gemini API to analyze raw packet/flow parameters, write natural language executive summaries, map attacks to MITRE ATT&CK TTPs, and produce SIGMA detection rules.
3. **Interactive Dashboard**: A premium React + Vite frontend using a dark space aesthetic, glassmorphism, Recharts visualization, and collapsible detail panels.
4. **DevOps Orchestration**: Standard Docker Compose containerization for local development and demonstration.
5. **Traffic Simulation**: A background simulator loop that streams synthetic network flows to mock real-time detection on the dashboard.

---

## User Review Required

> [!IMPORTANT]
> **Gemini API Key Setup**: For the AI threat summaries to function, a `GEMINI_API_KEY` needs to be defined. You can obtain a free API key from [Google AI Studio](https://aistudio.google.com/apikey). We will add a fallback mock mode for the AI engine if no key is provided, so the app remains fully functional out of the box.
>
> **Workspace Location**: All project files will be created in the current empty workspace folder: `d:\projects\NetShield`.

---

## Open Questions

> [!NOTE]
> There are no remaining blockers. We will proceed with generating a mock dataset containing network flow records for training and real-time simulator playback, eliminating the need to download huge PCAP datasets.

---

## Proposed Changes

We will populate the project structure as follows:

```
NetShield/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── routes.py          # REST endpoints (health, analyze, alerts, stats, simulation)
│   │   ├── ml/
│   │   │   ├── __init__.py
│   │   │   ├── model.py        # ML prediction pipeline wrapper
│   │   │   └── train.py        # Model training script
│   │   ├── ai/
│   │   │   ├── __init__.py
│   │   │   └── engine.py       # Gemini API analysis and SIGMA generation
│   │   ├── store/
│   │   │   ├── __init__.py
│   │   │   └── alert_store.py  # SQLAlchemy schemas & CRUD methods
│   │   └── simulator/
│   │       ├── __init__.py
│   │       └── live_feed.py    # Background thread simulating network traffic flow
│   ├── models/
│   │   ├── .gitkeep
│   ├── Dockerfile
│   ├── main.py                # FastAPI server entry point
│   └── requirements.txt       # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AlertFeed.jsx  # Table of active security alerts
│   │   │   ├── AttackChart.jsx # Recharts visualizations (Pie/Bar)
│   │   │   ├── Header.jsx      # Title & simulator controls
│   │   │   ├── StatsCards.jsx  # KPI metrics (alerts, severity, accuracy)
│   │   │   └── ThreatSummary.jsx # Collapsible threat intelligence viewer
│   │   ├── styles/
│   │   │   └── index.css      # Dark-mode glassmorphic CSS rules
│   │   ├── App.jsx            # Main view aggregator & state coordinator
│   │   └── main.jsx           # Vite entrypoint
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
├── data/
│   └── generate_mock_dataset.py # Script to create a synthetic CICIDS2017 CSV
├── docker-compose.yml          # Container configuration (frontend, backend, database)
├── .env.example                # Sample environment configuration
└── README.md                   # In-depth README following SecFlow documentation style
```

### 1. Data Utility & ML Training

#### [NEW] [generate_mock_dataset.py](file:///d:/projects/NetShield/data/generate_mock_dataset.py)
Creates a synthetic CSV dataset matching CICIDS2017 features. It will contain about 10,000 rows with clear patterns for:
- `BENIGN`: Small flow durations, standard port traffic (80, 443), balanced forward/backward packets.
- `DDoS`: High volume of forward packets, short flow duration, destination port 80.
- `Port Scan`: Sequential destination ports, small packet sizes, quick flow duration.
- `Brute Force`: High forward packet rates, destination port 22/3389, multiple short connections.
- `Botnet`: Intermittent spikes on high ports, steady long-duration packet exchange.

#### [NEW] [train.py](file:///d:/projects/NetShield/backend/app/ml/train.py)
Cleans the synthetic CSV dataset (drops NaN/Infinity, scales features), trains a `RandomForestClassifier` with Scikit-learn, encodes labels using `LabelEncoder`, and saves the serialized `ids_model.pkl` and `label_encoder.pkl` model artifacts.

---

### 2. FastAPI Backend

#### [NEW] [requirements.txt](file:///d:/projects/NetShield/backend/requirements.txt)
Defines all backend libraries: `fastapi`, `uvicorn`, `pandas`, `scikit-learn`, `joblib`, `google-generativeai`, `sqlalchemy`, `psycopg2-binary`, `python-dotenv`.

#### [NEW] [main.py](file:///d:/projects/NetShield/backend/main.py)
Initializes the FastAPI application, mounts CORS rules (allowing the Vite frontend on port 5173), configures startup/shutdown events to verify the database and load the ML model artifacts, and launches the routes.

#### [NEW] [alert_store.py](file:///d:/projects/NetShield/backend/app/store/alert_store.py)
Configures the PostgreSQL engine via SQLAlchemy. Standardizes the SQL table schema for `alerts`:
- UUID primary key, Timestamp, Source/Destination IPs & Ports, Attack Type, Confidence, Severity, Raw features JSON, and the AI-generated Threat Summary.

#### [NEW] [model.py](file:///d:/projects/NetShield/backend/app/ml/model.py)
A helper to load `ids_model.pkl` and `label_encoder.pkl` at server start. Exposes a `predict(features)` function mapping the 40+ numerical features to a classification label and calculating a confidence score.

#### [NEW] [engine.py](file:///d:/projects/NetShield/backend/app/ai/engine.py)
Connects to the Gemini SDK using `google-generativeai`. Sends details of a classified attack (e.g. DDoS detected from IP 192.168.1.50 with 95% confidence) to generate an analyst-focused response:
- Executive summary of the vulnerability/attack vector.
- Mapping to MITRE ATT&CK TTPs (e.g., T1498 for Network Denial of Service).
- A SIGMA rule snippet detailing detection filters for security information management.

#### [NEW] [live_feed.py](file:///d:/projects/NetShield/backend/app/simulator/live_feed.py)
An asynchronous background task manager. When started, it reads rows from the mock dataset, passes them through the classification pipeline, and inserts alert rows into the SQL store at 1-second intervals.

#### [NEW] [routes.py](file:///d:/projects/NetShield/backend/app/routes.py)
Exposes the REST API surface:
- `GET /api/health` -> Server status.
- `GET /api/alerts` -> Reads the recent 50 alerts from PostgreSQL.
- `GET /api/stats` -> Returns aggregated metrics: total alerts, count by severity (Critical, High, Medium, Low), and count by attack category.
- `POST /api/simulate/start` & `POST /api/simulate/stop` -> Controls the background network traffic simulator state.

---

### 3. React Frontend

#### [NEW] [index.css](file:///d:/projects/NetShield/frontend/src/styles/index.css)
Injects visual styling:
- Dark cyber aesthetic with color palette `#0a0b10` (deep space background) and glowing neon highlights (emerald for safe, crimson for critical attacks).
- Glassmorphic panels using CSS backdrop filters and subtle borders.
- Monospaced typography for network packets and code logs.

#### [NEW] [App.jsx](file:///d:/projects/NetShield/frontend/src/App.jsx)
Orchestrates client-side state:
- Periodically polls `/api/alerts` and `/api/stats` to render real-time telemetry.
- Controls the simulation start/stop state by triggering backend endpoints.
- Manages detail panel toggle states when a user clicks on an active alert row.

#### [NEW] [components/](file:///d:/projects/NetShield/frontend/src/components/)
- **Header.jsx**: Controls simulation toggle buttons and shows running status indicators.
- **StatsCards.jsx**: KPI panels display Total Alerts, Critical Count, Model Accuracy (loaded dynamically), and Active Attack Types.
- **AttackChart.jsx**: Visualizes attack breakdowns using Recharts (e.g. Doughnut chart of attack frequency).
- **AlertFeed.jsx**: Displays logs in a table with color-coded severity badges.
- **ThreatSummary.jsx**: Embeds the markdown summary produced by Gemini (executive summary, MITRE ATT&CK, SIGMA rules) in a nice panel with a copy button.

---

### 4. Docker & Project Config

#### [NEW] [docker-compose.yml](file:///d:/projects/NetShield/docker-compose.yml)
Coordinates the runtime services:
1. `netshield-db`: PostgreSQL database with health checks.
2. `netshield-backend`: FastAPI server reading environment variables.
3. `netshield-frontend`: Vite development server mapped to port 5173.

#### [NEW] [README.md](file:///d:/projects/NetShield/README.md)
A detailed documentation file including shields, system architecture diagrams, installation guide, walkthroughs, and API references.

---

## Verification Plan

### Automated Tests
- Run `python backend/app/ml/train.py` locally to verify model training completes successfully and writes `.pkl` files to `backend/models`.
- Run `docker compose up --build` to verify that all containers start successfully, the Postgres database initializes the schema, and the FastAPI application connects to it.

### Manual Verification
- Open the dashboard at `http://localhost:5173`.
- Click "Start Simulator" to begin simulated traffic.
- Verify that attack entries populate the "Live Alert Feed" in real-time, matching the synthetic dataset distribution.
- Click on any alert to check the expanded detail panel: verify the parameters, confidence level, and AI threat summary.
- Run browser print layout to verify dashboard exports cleanly to PDF.
