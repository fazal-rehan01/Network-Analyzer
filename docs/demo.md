# Demo Script

Complete end-to-end demonstration workflow for evaluators and teachers.

## Prerequisites

- Backend running on `http://localhost:8000`
- Frontend running on `http://localhost:5173`
- TShark/Wireshark installed with Npcap (Windows) or loopback (Linux)
- Zeek optional (not required for core demo)

---

## Step-by-Step Demo

### 1. Dashboard Overview
- Open http://localhost:5173
- Observe empty state: no captures, no incidents, zero analytics

### 2. Start a Live Capture
- Navigate to **Capture** page
- Select **Npcap Loopback Adapter** (Windows) or **lo** (Linux)
- Click **Start Capture**
- Leave it running

### 3. Run Port Scan Simulation
- Navigate to **Simulation** page
- Verify target is `127.0.0.1`
- Click **Run scenario** on **Port Scan Simulation** card
- Watch status: `idle` → `queued` → `running` → `completed`
- Observe packet/connection counters increment in real time

### 4. Verify Captured PCAP
- Return to **Capture** page
- Click **Stop Capture**
- A new PCAP row appears with:
  - Non-zero packet count
  - Duration matching capture window
  - File size > 0

### 5. Normalize the Capture
- Navigate to **Correlated** page
- Select the capture you just created from the dropdown
- Click **Run Normalization**
- Wait for completion (TShark parses PCAP → normalized records)
- Verify: connections, DNS records, HTTP records appear in tables

### 6. Inspect Normalized Packets
- Navigate to **Packets** page
- Select the same capture
- Browse packet list with filters (protocol, port, search)
- Click a row to see **Packet Details** (TShark evidence)

### 7. Run Detection
- Navigate to **Detect** page
- Select the capture
- Click **Run Detection**
- **Verify:** `Possible Port Scan` finding appears
  - Severity: High (configurable threshold)
  - Evidence: references specific connection records
  - Rule: port scan detection logic explained in UI

### 8. Examine Finding Evidence
- Click the finding to open **Finding Details**
- Observe **Evidence** section: each reference links to a normalized connection record
- Click a reference to jump to that record in Packets/Correlated view

### 9. Promote to Incident
- Navigate to **Incidents** page
- Click **Create Incident** on the port scan finding
- Incident created with status `NEW`
- Verify: severity preserved, evidence linked, finding marked as promoted

### 10. Demonstrate Incident Lifecycle
- Open the incident detail
- Change status: `NEW` → `INVESTIGATING`
- Add an **investigation note** (e.g., "Confirmed port scan from simulation")
- Change status: `INVESTIGATING` → `CONTAINED`
- Add another note (e.g., "Simulated traffic only, no real threat")
- Change status: `CONTAINED` → `RESOLVED`
- Observe: `closed_at` timestamp populated, history records each transition

### 11. Dashboard Analytics
- Navigate to **Dashboard**
- Verify real data:
  - Total packets / connections / bytes > 0
  - Packets/sec chart shows activity
  - Open incidents = 1 (or 0 if resolved)
  - High/Critical incidents count matches
  - Protocol distribution shows TCP dominant
  - Top talkers/conversations reflect scan pattern
  - Detection/incident severity charts populated

### 12. TShark vs Zeek Comparison
- Navigate to **Compare** page
- Select the capture
- Observe:
  - **TShark side:** packet-level data (frames, timestamps, lengths, ports)
  - **Zeek side:** shows "Zeek unavailable" (honest unavailable state)
  - **Correlation status:** TShark-only for all connections
  - No fake Zeek data is displayed

### 13. Generate PDF Report
- Navigate to **Reports** page
- Select **Global** (or specific capture)
- Click **Generate Report**
- Download PDF and verify it contains:
  - Capture scope
  - Simulation history
  - Traffic summary
  - Detection findings with evidence
  - Packet-level (TShark) analysis
  - Event-level (Zeek) analysis — marked unavailable
  - TShark vs Zeek comparison
  - Data-driven recommendations

---

## Expected Outcomes Checklist

- [ ] Live capture produces real PCAP with packets
- [ ] Port scan simulation generates TCP SYN traffic to multiple ports
- [ ] Normalization creates connection/DNS/HTTP records from TShark
- [ ] Detection rule fires on port scan pattern
- [ ] Finding evidence references are traceable to normalized records
- [ ] Incident lifecycle transitions work correctly
- [ ] Dashboard analytics reflect the analyzed data
- [ ] Comparison page honestly reports Zeek unavailable
- [ ] PDF report generates without errors

---

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| "No interfaces found" | Install Npcap (Windows) or run as root (Linux) |
| "tshark not found" | Set `TSHARK_PATH` in `.env` or add to PATH |
| "Zeek unavailable" | Expected if Zeek not installed; TShark path still works |
| Simulation stuck at "stopping" | Restart backend (stale runners cleaned on startup) |
| Dashboard shows zeros | Ensure normalization and detection completed for a capture |

---

## Notes for Evaluators

- **All traffic is localhost-only** — no external network access
- **Detection is rule-based** — no ML/AI, fully explainable
- **Database is SQLite** by default — file at `backend/traffic.db`
- **PCAPs stored in** `backend/storage/pcaps/`
- **Reports generated to** `backend/storage/reports/`