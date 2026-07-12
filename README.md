# SBOM Software Supply Chain Risk Analyzer

An enterprise-grade Software Bill of Materials (SBOM) ingestion, dependency mapping, risk calculation, and AI-driven remediation platform.

---

## 🚀 Key Features

* **CycloneDX Ingestion**: Ingests, normalizes, and validates standard CycloneDX JSON SBOM specifications.
* **Dependency Graph Analysis**: Leverages `NetworkX` to construct high-performance dependency trees, identify reachability paths, and distinguish between direct and transitive package routes.
* **License Compliance Engine**: Evaluates packages against business policies (e.g. GPL copyleft blocks in proprietary applications).
* **Multi-Factor Risk Scoring**: Calculates weighted risk metrics taking CVSS scores, maintenance staleness, license types, business criticality, and patch availability into account.
* **AI Intelligence Layer**: Powered by **Mistral AI (`mistral-large-latest`)** to generate executive summaries, explain root-causes, prioritize fixes, and propose remediation actions.
* **Interactive Frontend**: Features dynamic analytics dashboards, interactive dependency tree routing utilizing **React Flow**, and exportable reports.

---

## 🛠️ Technology Stack

### Backend
| Component | Technology | Role |
| :--- | :--- | :--- |
| **Language** | Python >= 3.12 | Core backend engine. |
| **Package Manager** | `uv` | Dependency resolution and locking (`uv.lock`). |
| **Web Server** | FastAPI + Uvicorn | Hosts the REST API endpoints. |
| **Graph Analysis** | NetworkX | Analyzes complex package dependency trees. |
| **Data Processing** | Pandas | Coordinates SBOM and vulnerability database files. |
| **AI Integration** | Mistral AI API | Translates risk profiles into human-readable narratives. |

### Frontend
| Component | Technology | Role |
| :--- | :--- | :--- |
| **Framework** | React 19 + TypeScript | UI component runtime. |
| **Bundler** | Vite | Ultra-fast client compilation. |
| **Styling** | Tailwind CSS v4 | Utility-first dashboard styling. |
| **Network Graphs** | React Flow (`@xyflow/react`) | Renders interactive, zoomable dependency trees. |
| **Analytics Charts** | Recharts | Plots risk and severity distribution charts. |
| **State Management** | TanStack Query v5 | Server state caching and synchronization. |

---

## 📂 Project Structure

```
sbomriskanalyzer/
├── ai/                      # AI Context builders and LLM prompts
│   ├── prompts/             # Modular system instructions
│   └── models.py            # Mistral AI connection handler (with fallbacks)
├── backend/                 # FastAPI server codebase
│   ├── api/                 # REST routing and startup lifespans
│   └── services/            # Business logic and global state
├── data/                    # Databases and CycloneDX inputs
│   └── sample/              # Pre-generated test datasets
├── frontend/                # React dashboard source code
│   ├── src/pages/           # Dashboard, Dependency Graph, Reports views
│   └── src/components/      # Reusable widgets and KPI charts
├── reports/                 # Export engines (JSON/HTML/PDF)
│   └── output/              # Target directory for generated reports
├── README.md                # General system documentation
└── pyproject.toml           # Python package requirements
```

---

## 🔌 Quick Start

### 1. Prerequisites
Ensure you have **Python >= 3.12** (with `uv` recommended) and **Node.js** installed on your system.

### 2. Configure Environment Variables
Create a file named [`.env`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/.env) in the project root:
```env
MISTRAL_API_KEY=your_actual_mistral_api_key_here
```
*(If no API key is specified, the application will automatically fall back to programmatic mock data so that all features continue to function seamlessly).*

### 3. Run the Backend API
In the project root, run:
```bash
uv sync
uv run python -c "from backend.api.main import run; run()"
```
The backend starts up and listens at **`http://localhost:8000`**.

### 4. Run the Frontend Dashboard
In a separate terminal window:
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser to access the dashboard.

---

## 🧪 Verification & Testing

Verify separate sub-systems using the built-in python verification scripts:

```bash
uv run python verify_parser.py     # Check CycloneDX ingestion
uv run python verify_loader.py     # Verify cross-dataset consistency
uv run python verify_license.py    # Test compliance engine compatibility
uv run python verify_risk.py       # Check weighted score engine
uv run python verify_graph.py      # Test reachability and visualization
uv run python verify_ai_layer.py   # Run AI prompt & report exports
```
