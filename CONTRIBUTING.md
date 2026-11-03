# Contributing to AI-Powered SDN Network Guardian 🛡️

First off, thank you for considering contributing to **AI-Powered SDN Network Guardian**! This project is **100% Open Source** under the [MIT License](LICENSE), and we welcome contributions of all kinds—from new machine learning anomaly detectors and OpenFlow 1.3 mitigation policies to frontend NOC dashboard visualizations, bug fixes, and documentation improvements.

---

## 🚀 How to Contribute (Step-by-Step)

### 1. Fork & Clone the Repository
1. Click the **Fork** button at the top-right of [https://github.com/Rahulchaube1/SDN](https://github.com/Rahulchaube1/SDN).
2. Clone your forked repository locally:
   ```bash
   git clone https://github.com/<your-username>/SDN.git
   cd SDN
   git remote add upstream https://github.com/Rahulchaube1/SDN.git
   ```

### 2. Create a Feature or Bugfix Branch
Always create a descriptive branch off `main`:
```bash
git checkout -b feat/your-feature-name
# or
git checkout -b fix/your-bugfix-name
```

### 3. Set Up Your Local Development Environment

#### Backend, Controller & ML Engine (Python 3.10+)
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS / WSL2:
# source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

Start the FastAPI backend locally:
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend NOC Dashboard (Node.js 18+ / React 18 / Vite)
```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

### 4. Run Tests Before Committing
Ensure all unit tests, integration tests, and frontend builds succeed cleanly:
```bash
# 1. Run Python automated test suite (8 tests across Detection, Controller, Mitigation, FastAPI & SQLite):
python -m unittest discover -s tests -v

# 2. Verify all 4 SDN scenarios:
python -m network.scenarios.scenario_a_normal
python -m network.scenarios.scenario_b_detection
python -m network.scenarios.scenario_c_mitigation
python -m network.scenarios.scenario_d_recovery

# 3. Verify frontend production build:
cd frontend && npm run build
```

### 5. Commit & Open a Pull Request
Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`):
```bash
git add -A
git commit -m "feat: add new anomaly detector or dashboard feature"
git push origin feat/your-feature-name
```
Then open a **Pull Request** against `Rahulchaube1/SDN` (`main` branch).

---

## 💡 High-Impact Areas for Contributors
- **AI / ML Detection (`detection/`):** Add new lightweight classifiers (e.g., Gradient Boosted Trees, Autoencoders, LSTM flow-sequence detectors) over the 7-dimensional OpenFlow feature space.
- **SDN Controller & OpenFlow 1.3 (`controller/`):** Add multi-table pipeline policies (`OFPInstructionGotoTable`), DSCP QoS remarking, or sFlow/IPFIX hybrid telemetry support.
- **Mininet Topologies (`network/`):** Contribute Spine-Leaf data-center topologies or multi-controller East-West topologies.
- **NOC Dashboard (`frontend/`):** Add dark/light theme toggles, Pcap/CSV export buttons, or custom topology layout editors.

---

## 📜 License
By contributing to this repository, you agree that your contributions will be licensed under its [MIT License](LICENSE).
