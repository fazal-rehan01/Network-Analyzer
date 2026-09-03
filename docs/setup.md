# Setup Guide

Complete installation instructions for Windows, Linux/WSL, and macOS.

---

## Current Verified Environment (M1)

| Tool | Version | Status |
|------|---------|--------|
| Python | 3.12.0 | ✅ |
| Node.js | 24.11.0 | ✅ |
| npm | 11.19.0 | ✅ |
| Git | 2.55.0 | ✅ |
| TShark/Wireshark | 4.6.7 | ✅ at `C:\Program Files\Wireshark\tshark.exe` |
| Zeek | — | ❌ Not installed (optional) |
| Docker | Installed | ⚠️ Daemon not running (optional) |

---

## Windows Setup (Recommended for Evaluators)

### 1. Install Prerequisites

**Python 3.12**
```powershell
# Via winget (recommended)
winget install Python.Python.3.12

# Or download from python.org
```

**Node.js 24 + npm**
```powershell
# Via winget
winget install OpenJS.NodeJS.LTS

# Or download from nodejs.org
```

**Git**
```powershell
winget install Git.Git
```

**TShark/Wireshark (REQUIRED for live capture)**
```powershell
# Install Wireshark (includes TShark + Npcap)
winget install WiresharkFoundation.Wireshark

# During Npcap install: select "Install Npcap in WinPcap API-compatible Mode"
```

**Zeek (OPTIONAL)**
- Windows native Zeek is experimental
- Use WSL2 + Linux Zeek for production use
- The application works fully without Zeek (TShark-only mode)

**Docker (OPTIONAL)**
```powershell
winget install Docker.DockerDesktop
```
- Only needed if you want containerized lab targets

### 2. Clone Repository

```powershell
git clone https://github.com/VarunParmar0206/NetworkChuck.git
cd NetworkChuck
```

### 3. Backend Setup

```powershell
cd backend

# Create virtual environment
python -m venv .venv

# Activate
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Verify TShark detection
python -c "from app.utils.tools import find_tool; print(find_tool('tshark'))"
# Should print path like: C:\Program Files\Wireshark\tshark.exe
```

### 4. Frontend Setup

```powershell
cd frontend

# Install dependencies
npm install

# Verify build works
npm run build
```

### 5. Configure Environment (Optional)

```powershell
cd backend
copy .env.example .env
```

Edit `.env` if needed:
```ini
DATABASE_URL=sqlite:///./traffic.db
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
ZEEK_PATH=           # Leave empty if not installed
STORAGE_DIR=storage
MAX_UPLOAD_MB=100
```

### 6. Run the Application

**Terminal 1 — Backend**
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --port 8000
```

**Terminal 2 — Frontend**
```powershell
cd frontend
npm run dev
```

Open **http://localhost:5173** in browser.

---

## Linux / WSL2 Setup

### 1. Install Prerequisites

```bash
# Ubuntu/Debian/WSL2
sudo apt update
sudo apt install -y python3.12 python3.12-venv nodejs npm git tshark wireshark-common

# Zeek (optional but recommended on Linux)
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update && sudo apt install -y zeek

# Docker (optional)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

**Important:** Add user to `wireshark` group for non-root capture:
```bash
sudo usermod -aG wireshark $USER
# Log out and back in
```

### 2. Clone & Setup (same as Windows but with bash)

```bash
git clone https://github.com/VarunParmar0206/NetworkChuck.git
cd NetworkChuck

# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### 3. Run

```bash
# Terminal 1
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000

# Terminal 2
cd frontend
npm run dev
```

Open **http://localhost:5173**

---

## macOS Setup

```bash
# Via Homebrew
brew install python@3.12 node git wireshark zeek

# Zeek on macOS
brew install zeek

# Clone & setup (same as Linux)
git clone https://github.com/VarunParmar0206/NetworkChuck.git
cd NetworkChuck

cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cd ../frontend
npm install

# Run
# Terminal 1: cd backend && source .venv/bin/activate && uvicorn app.main:app --reload --port 8000
# Terminal 2: cd frontend && npm run dev
```

---

## Verify Installation

### Backend Health Check
```bash
curl http://localhost:8000/api/v1/system/health
# {"status":"ok","components":{"database":"ok","tshark":"ok","zeek":"unavailable"}}
```

### Frontend Loads
- Open http://localhost:5173
- Dashboard should show "System Status" with green checks for Database and TShark

### Run Tests
```bash
# Backend
cd backend
source .venv/bin/activate  # or .\.venv\Scripts\Activate.ps1 on Windows
pytest -v

# Frontend
cd frontend
npm run typecheck
npm run lint
npm run build
```

All 172 backend tests should pass.

---

## Troubleshooting

### TShark Not Found
```powershell
# Windows: Add to PATH or set in .env
$env:PATH += ";C:\Program Files\Wireshark"
# Or edit backend/.env:
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
```

### "No interfaces available" on Windows
- Install Npcap with "WinPcap API-compatible Mode" checked
- Run terminal as Administrator for first capture
- Or use `.\.venv\Scripts\Activate.ps1` from elevated PowerShell

### Zeek "unavailable" on Windows
- **This is expected.** The application works without Zeek.
- Comparison page will show "Zeek unavailable" honestly.
- To enable: use WSL2 with Linux Zeek, or install Zeek via Chocolatey (experimental).

### Database Errors
```powershell
# Reset database
cd backend
del traffic.db
del -r storage\pcaps\*
del -r storage\reports\*
# Restart backend — DB recreates automatically
```

### Port 8000/5173 Already in Use
```powershell
# Kill existing processes
netstat -ano | findstr :8000
taskkill /PID <PID> /F

netstat -ano | findstr :5173
taskkill /PID <PID> /F
```

### Frontend Build Fails
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

---

## Project Directories (Created at Runtime)

```
backend/
├── traffic.db              # SQLite database (auto-created)
├── storage/
│   ├── pcaps/              # Captured/uploaded PCAP files
│   ├── reports/            # Generated PDF reports
│   └── zeek/               # Zeek log output (if enabled)
└── .venv/                  # Python virtual environment

frontend/
├── dist/                   # Production build output
└── node_modules/           # npm dependencies
```

All `storage/` and `dist/` directories are gitignored.

---

## Next Steps

1. Follow the **Quick Demo** in `README.md` or `docs/demo.md`
2. Explore the **API documentation** at http://localhost:8000/docs (FastAPI Swagger UI)
3. Review `docs/architecture.md` for system design
4. Check `docs/detection-rules.md` for detection logic details