# Architecture, Algorithms, and UI Design Specifications

This document provides a detailed technical overview of the SBOM Software Supply Chain Risk Analyzer's system architecture, mathematical analysis algorithms, and frontend user interface design.

---

## 1. System Architecture

The platform uses a decoupled, multi-layered architecture designed to process complex Software Bill of Materials (SBOM) data, calculate supply chain risks in real time, and layer AI insights asynchronously.

```mermaid
graph TD
    A[CycloneDX JSON Upload] --> B[Ingestion & Parsing Layer]
    B --> C[Graph Construction Layer - NetworkX]
    C --> D[Data Loader & Consistency Validator]
    D --> E[In-Memory State Manager - Thread-safe State]
    E --> F[Analysis & Evaluation Engines]
    
    subgraph Evaluation Layer
        F1[Weighted Risk Scoring Engine]
        F2[License Compatibility Engine]
        F3[Maintenance Risk Tracker]
    end
    F --> F1 & F2 & F3
    
    F1 & F2 & F3 --> G[AI Context & Intelligence Layer]
    G --> H[FastAPI REST API Layer]
    H --> I[React / Vite Frontend Dashboard]
end
```

### Architectural Layers

1. **Ingestion & In-Memory State Layer**
   * **State Manager**: Located in [`backend/services/analysis_state.py`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/backend/services/analysis_state.py). It acts as a thread-safe global singleton containing the current application registry, unified vulnerability database, license compliance rules, and active dependency graphs.
   * **Asynchronous Rebuild Threading**: To keep file uploads fast, the pipeline splits graph compilation (instant) from AI completions. An asynchronous background daemon thread handles LLM prompts, while metadata and risk scores are calculated immediately.

2. **Graph Construction Layer**
   * **Dependency Mapping**: Built using `NetworkX` ([`graph_analyzer.py`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/graph_analyzer.py)). It represents applications as roots and third-party libraries as downstream vertices. 

3. **AI Context Layer**
   * **Context Builder**: Combines graph statistics, license evaluations, and CVE records into a single, standardized **Risk Context JSON** payload ([`ai/context_builder.py`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/ai/context_builder.py)).
   * **AI Intelligence Services**: Modular service endpoints ([`ai/explanation_service.py`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/ai/explanation_service.py), [`ai/remediation_service.py`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/ai/remediation_service.py), etc.) communicate with **Mistral AI (`mistral-large-latest`)** using `urllib` calls optimized with connection headers, timeouts, and unverified SSL fail-safes.

---

## 2. Analysis & Calculation Algorithms

### A. Graph Traversal & Dependency Extraction
The platform reads CycloneDX JSON specifications, specifically extracting:
* **Components**: Declared libraries and their metadata (puris, licenses).
* **Dependencies**: A list of `bom-ref` associations mapping parent libraries to children.

Using these associations, `SBOMDependencyGraph` constructs a directed graph $G = (V, E)$ where:
* Vertices $V$ represent applications or libraries.
* Directed edges $E = (u, v)$ represent package dependencies (where $u$ depends on $v$).

**Algorithms applied**:
* **Breadth-First Search (BFS)**: Traverses successors of an application vertex to catalog all reachable downstream libraries.
* **Transitive Differentiation**: Any dependency $d$ reachable in $G$ from the application root $r$ where path length $L(r, d) > 1$ is marked as **Transitive**; if $L(r, d) = 1$, it is **Direct**.
* **Shortest Path Analysis**: Utilized to trace paths leading from the application root to vulnerable libraries (e.g. tracking down how an unpatched log4j vulnerability enters the system).

---

### B. License Compatibility Algorithm
The license engine ([`license_engine.py`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/license_engine.py)) checks license compliance based on:
1. **Target Distribution Mode**: (e.g., `saas`, `proprietary`, `redistributed`).
2. **Linking Type**: (e.g., `static`, `dynamic`).
3. **Copyleft Level**: (e.g., Permissive, Weak Copyleft, Strong Copyleft).

**Boolean Evaluation Logic**:
* **Permissive Licenses** (MIT, Apache-2.0, BSD): Automatically marked as `Compatible`.
* **Copyleft (AND/OR Conjunctive Rules)**:
  * For multi-licensed libraries declared as `License-A OR License-B`, the engine evaluates compatibility for both and chooses the **least restrictive** option.
  * For libraries declared as `License-A AND License-B`, the engine evaluates both and returns the **most restrictive** (limiting) compatibility status.
* **Strong Copyleft** (GPL-3.0, AGPL-3.0): Flagged as `Incompatible` if the target application is proprietary and distributed.

---

### C. Multi-Factor Weighted Risk Scoring
The risk scoring algorithm ([`risk_engine.py`](file:///c:/Users/Sys/Documents/sbomriskanalyzer/risk_engine.py)) calculates a score from `0` (no risk) to `100` (critical risk) using six weighted dimensions:

$$\text{Risk Score} = w_v \cdot S_v + w_l \cdot S_l + w_m \cdot S_m + w_d \cdot S_d + w_c \cdot S_c + w_p \cdot S_p$$

#### Scoring Dimensions & Weight Distributions

| Dimension | Key | Max Weight ($w$) | Raw Score Determination ($S$) |
| :--- | :---: | :---: | :--- |
| **Vulnerabilities** | $S_v$ | **40%** | Derived from the peak CVSS score of active CVEs ($S_v = \text{max}(\text{CVSS}) \times 10$). |
| **License Compliance** | $S_l$ | **20%** | Incompatible = 100; Needs Review = 50; Compatible = 0. |
| **Maintenance Staleness** | $S_m$ | **15%** | Scaled linearly up to 100 for libraries with no releases for $\ge 24$ months. |
| **Dependency Depth** | $S_d$ | **10%** | Direct libraries receive 100; transitive libraries receive 70 (representing isolated risk). |
| **Business Criticality** | $S_c$ | **10%** | Critical = 100; High = 75; Medium = 50; Low = 25. |
| **Patch Availability** | $S_p$ | **5%** | Active vulnerabilities with no official patch availability = 100; patched = 20. |

---

## 3. User Interface Design

The frontend is built with a cohesive dark cyberpunk aesthetic, prioritizing clarity, visual feedback, and quick interaction.

### Visual Design Tokens
* **Backgrounds**: Slate dark theme (`bg-cyber-950`, `bg-cyber-900`) for high-contrast visibility.
* **Accent Colors**: Cyber Cyan (`text-cyber-accent`) for highlights, links, and selections.
* **Risk Badges**:
  * **Critical**: Ruby Red (`bg-red-500/10 text-red-400 border-red-500/20`)
  * **High**: Amber Orange (`bg-orange-500/10 text-orange-400 border-orange-500/20`)
  * **Medium**: Canary Yellow (`bg-yellow-500/10 text-yellow-400 border-yellow-500/20`)
  * **Low / Safe**: Emerald Green (`bg-green-500/10 text-green-400 border-green-500/20`)

### Core Frontend Views

1. **Dashboard Page**
   * **KPI Grid**: Displays key metrics (e.g. overall risk score, total dependencies, maintenance alerts, and license violations).
   * **Analytics Charts**: Custom `Recharts` SVG components visualizing vulnerability severity spreads and top risky applications.

2. **Applications Catalog**
   * Displays all tracked software items in a sorted table by peak risk score.
   * Clicking a row opens a details panel containing a multi-tab sidebar (Overview, Dependency Graph, CVE lists, Licenses, and AI Explanations).

3. **Interactive Graph Visualizer**
   * Uses `React Flow` to render zoomable network nodes mapping out the dependency tree.
   * High-risk libraries or copyleft conflicts are highlighted in orange/red, providing an intuitive way to trace transitive risk paths.

4. **Reports Tab**
   * Provides executive security summaries, priority ranking metrics, and downloadable JSON/HTML summaries of the entire scanned fleet.
