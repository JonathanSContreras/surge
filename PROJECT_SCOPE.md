# Senior Project Proposal

## Agentic Network Analysis Tool

---

## 1. Project Overview

This project aims to design and implement an **agentic network analysis tool** that autonomously explores, analyzes, and classifies vulnerabilities in a network environment. The agent follows workflows aligned with the **MITRE ATT\&CK framework** and integrates reconnaissance, vulnerability scanning, exploitation (controlled), and machine learning–based vulnerability classification.

The system will be presented through a **Next.js dashboard**, which provides real-time insights, vulnerability prioritization, **network topology mapping**, and interactive graph visualization powered by a **Graph Neural Network (GNN)**.

This tool demonstrates how **AI-driven decision-making agents** can support cybersecurity workflows by:

* Automating repetitive scanning and analysis tasks.
* Classifying vulnerabilities by severity.
* Visualizing high-risk areas of a network.
* Providing explainable patch recommendations.

---

## 2. Core Features & Functionality

### **Agent Workflow (LangChain/LangGraph)**

1. **Reconnaissance (Nmap)** – Identify hosts, open ports, and services.
2. **Decision-Making Engine** – Select next actions dynamically:

   * Log/report to dashboard.
   * Port scans (stealth, decoy, aggressive).
   * OS fingerprinting & service enumeration.
   * Vulnerability scans (Nmap NSE, OpenVAS, Nikto).
   * Prioritization based on CVSS/EPSS scoring.
   * Controlled exploitation attempts (Metasploit).
3. **Vulnerability Classification (PyTorch)** – Classify severity into None/Low/Medium/High/Critical.
4. **Learning Loop** – Agent adjusts exploration strategies based on network changes.

---

### **Database & Data Pipeline**

* Ingest **CVE/NVD** data through the NVD API.
* Store in a **PostgreSQL** database for fast querying.
* Maintain vulnerability history logs and exploit attempts.
* Provide structured input for classifier training.

---

### **Vulnerability Classifier**

* Built in **PyTorch**, trained with labeled vulnerability datasets.
* Classifies vulnerabilities into severity categories.
* Supports prioritization for exploitation and patch recommendation.

---

### **Network Topology Mapping**

* The system traces the **network stack** to build a map of the network architecture.
* Identifies **connected devices, open ports, and potential entry points**.
* Visualizes relationships between hosts and services as a dynamic **graph structure**.
* Powered by **graph-based methods (GNN)** to highlight risky connections or vulnerable nodes.
* Integrated directly into the dashboard for real-time visualization and monitoring.

---

### **Dashboard (Next.js)**

* Graphical representation of hosts, ports, services, and vulnerabilities.
* Dynamic **network topology map** using D3.js or Cytoscape.js.
* Risk callouts highlighting nodes identified by classifier/GNN.
* Displays CVSS/EPSS scores, classification, and exploitation status.
* Real-time updates from the agent via custom API routes.

---

### **Network Simulation Environment**

* Controlled testbed of hosts, clients, and services.
* Vulnerabilities introduced intentionally for analysis.
* Periodic reconfiguration to challenge the agent.
* Supports VM-based, containerized, or hybrid deployment.

---

## 3. Tools & Tech Stack

* **LLM Agent**: GPT-OSS or Claude via LangChain/LangGraph.
* **Scanning & Exploitation Tools**: Nmap, Nikto, OpenVAS, Metasploit.
* **ML/AI**: PyTorch (GNN + vulnerability classifier).
* **Backend**: Python (wrapping scanning & exploitation tools).
* **Frontend**: Next.js dashboard, D3.js/Cytoscape.js visualizations.
* **Database**: PostgreSQL (CVE/NVD data, logs).
* **Infrastructure**: VM cluster or cloud deployment (depending on scope).

---

## 4. Roles & Responsibilities

### **Brianna (Computer Science – AI/ML Engineer, PM, Database Engineer)**

* **AI/ML Development**:

  * Build PyTorch vulnerability classifier.
  * Develop GNN for network topology risk visualization.
* **Agent Development**:

  * Integrate LangChain/LangGraph with scanning/exploitation tools.
  * Implement MITRE ATT\&CK decision workflows.
* **Database Engineering**:

  * Design PostgreSQL schemas for vulnerabilities/logs.
  * Automate CVE/NVD ingestion pipeline.
* **Project Management**:

  * Track milestones, assign tasks, ensure timely delivery.

---

### **Jonathan Contreras (Computer Science – Infrastructure & Full Stack Engineer)**

* **Infrastructure & Cloud Architecture**:

  * Deploy backend and agent in cloud/VM environment.
  * Configure APIs to connect agent ↔ backend ↔ dashboard.
* **Full Stack Development**:

  * Build Next.js dashboard with real-time data feeds.
  * Implement topology visualization & vulnerability graphing.
* **System Integration**:

  * Ensure seamless communication between modules.
  * Support deployment on Vercel and custom servers.
* **Testing & QA**:

  * Create automated tests for agent/dashboards.
  * Validate system performance and scalability.

---

### **Sean Moaning (Cybersecurity – Network/Security Analyst)**

* **Network Testbed Development**:

  * Deploy and maintain vulnerable systems.
  * Configure dummy clients/servers with insecure settings.
* **Security Oversight**:

  * Ensure controlled/ethical exploit testing.
  * Validate realism of vulnerabilities.
* **Knowledge Contribution**:

  * Apply CompTIA Network+/Security+ knowledge to simulate enterprise-like attack surfaces.
  * Support proper configuration of Metasploit for controlled exploitation.
* **Ethics & Compliance Lead**:

  * Document safe research practices.
  * Ensure project aligns with academic and cybersecurity standards.
  * **Resilience & Red Teaming**:

  * Test system performance against firewalls, IDS/IPS, and simulated attacks.
  * Challenge the agent’s mapping and classification with red-team style maneuvers.


---

### **Tauren Mohamed (Cyber Engineer – Network Engineer)**

* **Network Engineering**:

  * Configure routers, switches, VLANs, and network services.
  * Design scalable, layered network topologies for testing.
* **Topology Mapping Support**:

  * Build simulated environments for **network stack tracing**.
  * Provide ground truth for validating the agent’s topology maps.
* **Dynamic Environment Maintenance**:

  * Reconfigure network regularly to test agent adaptability.
  * Introduce randomized conditions (e.g., new hosts, segmented subnets).
* **Deployment Engineering**:

  * Containerize services (Docker/Kubernetes) for flexible testbed deployment.
  * Automate environment spin-up/tear-down for repeatable experiments.
* **Traffic Simulation & Logging**:

  * Simulate realistic enterprise traffic (HTTP, FTP, SSH, VoIP).
  * Configure monitoring/logging tools (e.g., Wireshark, ELK stack) to validate agent’s detection accuracy.

---

## 5. Deliverables

1. **Agent Framework** – autonomous scanning, classification, and prioritization.
2. **PyTorch Vulnerability Classifier** – trained and integrated with agent.
3. **Next.js Dashboard** – real-time visualization and network topology mapping.
4. **Network Simulation Testbed** – dynamic, controlled environment.
5. **Final Report & Demo** – documentation, diagrams, and ethical analysis.

---

## 6. Expected Outcomes

* Demonstrate AI-powered decision-making for cybersecurity.
* Provide a working prototype capable of scanning, mapping, classifying, and visualizing vulnerabilities.
* Deliver a **dynamic network topology map** that traces devices, ports, and entry points.
* Show adaptability of the agent to dynamic network conditions.
* Create an educational tool bridging computer science, cybersecurity, and AI.
