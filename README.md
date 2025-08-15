# 🛡️ Web Vulnerability Scanner

A **full-stack**, **Docker-ready** web vulnerability scanner that combines **8 security scanning tools** into one unified system.  
Built with **FastAPI** (backend) and **Next.js** (frontend), this project allows you to scan websites for vulnerabilities directly from your browser without root access.

## 📌 Features

 **8 Integrated Scanners**:
  1. OpenVAS
  2. Nuclei
  3. OWASP ZAP
  4. Nikto
  5. testssl.sh
  6. Nmap
  7. Trivy
  8. OWASP Dependency-Check

 **Frontend**: Next.js with interactive result cards.
 **Backend**: FastAPI that orchestrates and parses scanner outputs.
 **Docker Deployment**: Works locally or on free hosts (Railway, Render, Fly.io) without root access.
 **No Manual Installations**: All scanner binaries are pre-bundled in Docker
  ## 🚀 How It Works

1. **Frontend (Next.js)**  
   - User enters a target URL.  
   - Sends a POST request to `/scan` endpoint.  
   - Displays results in interactive cards.

2. **Backend (FastAPI)**  
   - Receives target URL.  
   - Executes all scanners in `/scanners/` folder.  
   - Parses outputs into JSON format.  
   - Returns aggregated results to frontend.

3. **Scanner Scripts**  
   - Each scanner has its own script (e.g., `nuclei_scanner.py`).  
   - Uses `subprocess` to run binaries located in `/binaries/`.  
   - Output is parsed and returned as structured JSON.
