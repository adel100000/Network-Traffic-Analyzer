# 🛰️ Network Traffic Analyzer

A real-time **network threat detection dashboard** built with **FastAPI** and **React**, designed to monitor, analyze, and visualize network traffic activity while integrating live threat intelligence from multiple trusted cybersecurity APIs.

>  Built as a personal cybersecurity and full-stack development project to demonstrate advanced backend logic, API integration, and secure frontend visualization.

---

##  Features

- **IP Threat Analysis** — integrated with [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com) for live malicious activity checks.  
- **Real-Time Alert System** — automatically updates the dashboard with detected threat levels.  
- **Geolocation & ISP Lookup** — fetches detailed IP info using ipapi.co and ipinfo.io.  
- **Interactive Dashboard** — built with React + Tailwind, featuring bar, pie, and line charts to visualize captured traffic data.  
- **User Authentication** — secure login with JWT, password hashing, and role-based access control (admin/viewer).  
- **FastAPI Backend** — high-performance Python backend managing packet capture, IP scoring, and data flow to the frontend.  
- **Extensible API Architecture** — modular structure allows easy expansion with new data sources or visualizations.  

---

## Tech Stack

**Frontend**
- React + TypeScript  
- Tailwind CSS  
- Recharts (data visualization)

**Backend**
- FastAPI  
- SQLAlchemy  
- Uvicorn  
- PyShark & Scapy (network packet analysis)  
- Requests, Python-Jose, Passlib  

**Threat Intelligence APIs**
- VirusTotal  
- AbuseIPDB  
- ipapi.co  
- ipinfo.io  





##  Project Structure



##  Setup & Installation

### Backend Setup

Clone the repository:

```bash
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer/app
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Create a .env file inside the app/ directory with the following variables:

env
Copy code
SECRET_KEY=your_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
## You can get free API keys from:

VirusTotal Developer Portal

AbuseIPDB API Registration

Run the backend server:

bash
Copy code
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# Frontend Setup
Navigate to the frontend directory:

bash
Copy code
cd ../frontend
Install dependencies and start the dev server:

bash
Copy code
npm install
npm run dev
Open your browser and go to http://localhost:5173 (or the port specified).

## Authentication
The app supports role-based access:

Admin: Full access to all system features and threat management.

Viewer: Read-only dashboard view.

Example test credentials (for demo use):

makefile
Copy code
Username: me4
Password: me567
## Dashboard Preview
Preview screenshots coming soon.

 Placeholder sections:

Realtime Threat Activity Graph

IP Geolocation Map

Threat Level Distribution (Pie Chart)

Alert Feed and Logs

## Future Improvements
 Traffic Filtering by Protocols (TCP, UDP, HTTP)

 Historical Threat Log Storage and Export (CSV/JSON)

 Advanced Analytics and Time-Series Correlation

 Machine Learning Risk Scoring (future idea)

 Multi-factor Authentication for Admins

🧾 License
This project is licensed under the MIT License 

