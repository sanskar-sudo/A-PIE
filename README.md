
![Logo](https://cdn-icons-png.flaticon.com/128/8168/8168607.png)


# A-PIE
Modern, fast, and tasty malware API intelligence for rapid triage and research.
A-PIE is a Python-based web application that extracts and presents information about Windows API usage inside Portable Executable (PE) files. Upload a PE, see which APIs it imports/calls, explore aggregated intelligence, and export results for further analysis or reporting.



## Features


- Multi-API lookup – input multiple Windows APIs and get detailed info.

- PE upload & analysis – extract and map APIs from uploaded executables.

- Lightweight & fast – minimal overhead for rapid triage.

- Verbose mode – toggle extra context and details.

- Export to TXT – save results in plain text.

Designed for malware researchers, incident responders, and threat hunters.

## Installation


    

These commands assume you have Python 3.8+ installed.

Clone the repo:

```bash
git clone https://github.com/your-org/a-pie.git
cd a-pie
```



Create & activate a virtual environment:

```bash
python -m venv .venv
# macOS / Linux
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

```

Install dependencies:
```bash
pip install -r requirements.txt

```


Run the app:
```bash
python web_app.py
```

## Screenshots
<img width="984" height="890" alt="image" src="https://github.com/user-attachments/assets/7133b336-bc6e-4d4f-b8f6-a38d3e173c9d" />
<img width="984" height="890" alt="image" src="https://github.com/user-attachments/assets/88d13398-13fb-40ad-9a32-29330caf9e52" />


## Safety & Usage Warning ⚠️
Important: A-PIE performs static analysis of potentially malicious binaries. Do not execute untrusted binaries on your host machine. Always run A-PIE and any file-handling workflows inside an isolated, air-gapped, or sandboxed environment (VM, container, or dedicated lab). Follow your organization’s security policies and legal requirements when handling malware samples.
