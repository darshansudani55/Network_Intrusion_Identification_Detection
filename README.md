# Hybrid Network Intrusion Detection System
### Real-Time Detection of Port Scanning and DoS Attacks

A hybrid NIDS combining **signature-based rules** (deterministic thresholds, low
false-positive rate) with an **anomaly-based ML classifier** (RandomForest on
flow features) to detect port scans and DoS attacks in real time, with a live
web dashboard.

---

## 1. Project Structure

```
hybrid-nids/
├── backend/
│   ├── app/
│   │   ├── features/
│   │   │   ├── flow_extractor.py   # packets -> flow-level features
│   │   │   └── sniffer.py          # live capture via Scapy (needs root)
│   │   ├── detection/
│   │   │   ├── rule_engine.py      # signature-based thresholds
│   │   │   ├── ml_engine.py        # ML inference wrapper
│   │   │   └── hybrid.py           # fusion logic + Alert model
│   │   ├── simulate/
│   │   │   └── replay.py           # synthetic traffic generator (safe demo mode)
│   │   └── main.py                 # FastAPI app (REST + WebSocket)
│   ├── models/                     # trained model artifacts (generated)
│   ├── train_model.py              # ML training script
│   └── requirements.txt
├── frontend/
│   └── dashboard.html              # single-file live dashboard (no build step)
└── README.md
```

## 2. How the Hybrid Detection Works

**Signature engine** (`rule_engine.py`) — fixed thresholds:
- Port scan: a source IP touching ≥15 distinct destination ports within a
  10-second window → flagged, sub-classified as SYN/FIN/NULL scan by flag pattern.
- DoS: SYN-flood ratio, raw packet/sec volumetric threshold, and a
  long-duration/low-rate rule for Slowloris-style attacks.

**ML engine** (`ml_engine.py`) — RandomForestClassifier trained on 19 flow
features (duration, packet/byte counts, TCP flag counts, packets/sec, SYN:ACK
ratio, etc.), predicting `BENIGN / PortScan / DoS`. This catches variants that
don't cross the rule engine's fixed thresholds.

**Fusion** (`hybrid.py`) — OR logic: either engine triggering raises an alert.
Severity is CRITICAL when both agree, HIGH when only the rule engine fires
(deterministic, trusted), MEDIUM/HIGH when only ML fires depending on model
confidence. This rule-vs-ML agreement comparison is your report's main
"hybrid outperforms either alone" evidence — log both engines' verdicts
separately during evaluation so you can produce that comparison table.

## 3. Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Scapy needs libpcap; on Ubuntu (your LOQ setup):
```bash
sudo apt install libpcap-dev
```

## 4. Train the Model

```bash
python train_model.py                          # synthetic data (works out of the box)
python train_model.py --data /path/to/cicids2017_merged.csv   # real dataset
```

**To use real CICIDS2017 data:** download the CSVs from
[unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) —
specifically `Wednesday-workingHours.pcap_ISCX.csv` (DoS variants: Hulk,
GoldenEye, Slowloris, Slowhttptest) and `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`.
Merge/concat them into one CSV and pass via `--data`. The loader maps
CICIDS2017's native column names onto this project's feature schema
automatically (see `load_real_dataset()` in `train_model.py`).

This prints accuracy, a classification report, confusion matrix, and feature
importances — all report-ready. It also saves `models/rf_model.joblib`,
`scaler.joblib`, and `label_encoder.joblib`, which the API loads at startup.

## 5. Run the Backend

```bash
uvicorn app.main:app --reload --port 8000
```

On startup it automatically launches the **traffic simulator** (safe, synthetic
— no root or real network access needed) so the dashboard has live data
immediately. Switch traffic mode via the dashboard buttons or:

```bash
curl -X POST localhost:8000/api/simulate/mode \
  -H "Content-Type: application/json" -d '{"mode":"portscan"}'
# modes: benign | portscan | dos_volumetric | dos_slow
```

**Endpoints:**
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | current mode, active flow count, model status |
| POST | `/api/simulate/mode` | switch simulated traffic pattern |
| GET | `/api/alerts?limit=50&severity=CRITICAL` | recent alerts |
| POST | `/api/analyze/flow` | score one hand-built flow (manual testing) |
| WS | `/ws/live` | live alert stream for the dashboard |

## 6. Run the Dashboard

Just open `frontend/dashboard.html` directly in a browser (no build step) —
it connects to `localhost:8000` automatically. Use the four mode buttons to
switch between benign traffic, a port scan, a volumetric flood, and a
slow-rate DoS, and watch the alert feed + oscilloscope respond in real time.
This is the demo to run live in your viva.

## 7. Live Capture on Real Traffic (Optional, for the report's "real-world validation" section)

```bash
sudo -E $(which python3) -m app.features.sniffer
```
Requires root (raw sockets) and a real interface. **Only run this against
traffic you own or have explicit authorization to monitor** — same
responsible-scope discipline you already apply in your bug bounty work.
You can also point Scapy's `rdpcap()` at a saved `.pcap` (e.g. a CICIDS2017
capture) and feed packets through `HybridDetector.ingest_packet()` in a loop
for offline replay validation instead of live sniffing.

## 8. What to Put in Your Report

- **Architecture diagram**: capture → feature extraction → rule engine + ML
  engine (parallel) → fusion → alert/dashboard (matches section 2 above)
- **Confusion matrix + classification report** from `train_model.py` output
- **Feature importance chart** (also printed by `train_model.py`)
- **Hybrid vs. rule-only vs. ML-only comparison**: run the same traffic
  through each engine independently and tabulate detection rate / false
  positive rate — this is your novelty claim, so make it the centerpiece
  table
- **Detection latency**: time between attack packet #1 and the first alert
  (the `flush_expired` loop runs every 2s, so per-flow near-real-time alerts
  fire immediately on rule/ML hits — slow-DoS style attacks alert only once
  the flow ages past `SLOW_DOS_MIN_DURATION`, worth discussing as a
  deliberate trade-off between latency and false positives)
- **Screenshots of the live dashboard** mid-attack for the demo section

## 9. Known Limitations (be upfront about these in your report — it reads as rigor, not weakness)

- Synthetic training data ships by default so the pipeline runs out of the
  box; swap in real CICIDS2017 CSVs before drawing real accuracy conclusions
- Thresholds in `rule_engine.py` are hand-tuned starting points — justify or
  retune them against your actual validation traffic and report the
  sensitivity
- Flow timeout (5s) and scan window (10s) trade detection latency against
  memory/state growth — worth a short discussion of that trade-off
- No persistent storage/logging to disk yet (alerts live in an in-memory
  deque) — add a DB layer if your report requires historical analysis beyond
  the live session
