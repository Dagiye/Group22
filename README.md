# 🌐 Web Vulnarbility Scanner — Next-Gen Web Vulnerability Scanner  


Web Vulnarbility Scanner is a **full-stack web security scanning framework** that combines a **Python FastAPI backend** with a **Next.js + Tailwind frontend** to deliver **real-time, extensible vulnerability detection**.  
It is designed to help developers, researchers, and security teams identify a wide range of **injection flaws, misconfigurations, and logic issues** in modern web applications.  

## 🔍 Vulnerability Coverage  

### 1. Injection Attacks  
- **SQL Injection (sqli.py)**: classic, union-based, boolean-blind, time-based, second-order, JSON/REST/GraphQL injection, WAF bypass.  
- **NoSQL Injection (nosqli.py)**: MongoDB, CouchDB, regex queries, `$where`/$ne bypasses.  
- **LDAP Injection (ldap_injection.py)**: filter manipulation, escalation.  
- **XPath Injection (xpath.py)**: blind XPath, XML extraction.  
- **SSTI (ssti.py)**: Jinja2, Twig, Mustache, Freemarker → RCE.  
- **Command Injection (cmdi.py)**: OS commands, time-based/DNS exfiltration.  
- **CRLF Injection (crlf.py)**: HTTP response splitting, cache poisoning.  
- **HTTP Parameter Pollution (hpp.py)**: duplicate param exploitation.  
- **JSON Injection (jsoni.py)**: JSONP hijacking, prototype poisoning.  

### 2. Cross-Site Scripting  
- **Reflected**: GET/POST params, headers, URL fragments.  
- **Stored**: persistent via DB, forms, comments.  
- **DOM-Based**: sinks (`innerHTML`, `eval`, `document.write`).  
- **Mutation-Based**: auto-corrections triggering XSS.  
- **Polyglot Payloads**: SVG onload, scriptable vectors.  

### 3. File Path Attacks  
- **LFI**: `/etc/passwd`, PHP wrappers.  
- **RFI**: remote URLs.  
- **Traversal**: Windows/Unix traversal, double encoding.  
- **Upload**: malicious extensions, MIME spoofing.  

### 4. Authentication & Access Control  
- **CSRF**: missing/weak tokens, SameSite misconfig.  
- **IDOR**: horizontal/vertical privilege escalation.  
- **Session Issues**: weak JWTs, replay, fixation.  
- **Privilege Escalation**: hidden endpoints, role bypass.  

### 5. Business Logic  
- **Replay**: token reuse.  
- **Race Conditions**: double-spend.  
- **Pricing/Workflow**: discount abuse, subscription bypass.  

### 6. Advanced Attacks  
- **SSRF**: internal services, cloud metadata.  
- **XXE**: file disclosure, OOB DNS exfil.  
- **HTTP Smuggling**: CL/TE desync.  
- **Host Header Injection**: reset poisoning.  
- **Cache Poisoning**: param-based.  
- **CORS Misconfig**: `Access-Control-Allow-Origin: *`.  
- **Clickjacking**: frame busting bypass.  
- **WebSocket**: WS injection, unauthorized upgrades.  
- **Prototype Pollution**: client/server JS objects.  
- **CSS Injection**: data exfiltration via selectors.  

### 7. GraphQL  
- **Introspection**: schema leaks.  
- **Abuse**: nested queries, denial-of-service.  
- **Auth**: bypass via misconfigured resolvers.  

### 8. Passive Modules  
- **Headers**: missing security headers.  
- **Cookies**: weak flags.  
- **TLS Checks**: weak ciphers.  
- **Tech Fingerprinting**: stack discovery.  
- **Secrets Grep**: hardcoded keys/tokens.  

---

## ⚡ Features  

- Real-time WebSocket scan updates  
- Extensible payload templates (YAML, Jinja2)  
- Evidence storage: HAR, DOM snapshots, redaction  
- Report builders: HTML, PDF, JSON with remedies  
- Modular crawler: sitemap, AJAX, API discovery  
- Multi-auth: form login, token, OAuth/OIDC, SAML, MFA  
- Evasion techniques: encoding, polyglots, smuggling  
- Multi-config support: safe, aggressive, custom  

## 🚀 Getting Started  

### Backend (FastAPI)  
```bash
cd backend
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt

### the following the files placed at telegram group
backend/core/serviceAccountKey.json
backend/core/firebase-service-account.json
backend/services/firebase-service-account.json


## Run backend
uvicorn backend.apps.api.main:app --reload --host 0.0.0.0 --port 8001
### Frontend (Next.js)  
```bash
cd frontend
npm install
npm run build
npm run dev

make sure node_modules created during npm install 
