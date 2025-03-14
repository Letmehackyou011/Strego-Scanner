# Strego is a Advanced AI-Powered Vulnerability Scanner

## Overview
Strego is a highly advanced, AI-powered vulnerability scanner that integrates **100+ security tools** for penetration testing and cybersecurity assessments. It automates scanning, reporting, and exploit analysis, making security assessments faster and more effective.

## Features
- **Multi-threaded Scanning** for high-speed scanning
- **Integration of 100+ Security Tools**, including:
  - Nmap (Network scanning)
  - Nikto (Web server scanning)
  - Gobuster (Directory enumeration)
  - Wafw00f (WAF detection)
  - SQLmap (SQL injection testing)
  - Nuclei (Template-based vulnerability scanning)
  - Hydra (Brute-force attacks)
  - Metasploit, XSStrike, Sublist3r, Shodan, Amass, TheHarvester, and many more!
- **AI-Driven Risk Analysis** using TensorFlow to predict vulnerability severity
- **Automated Exploitation** for detected vulnerabilities
- **JSON & HTML Reporting for easy readability**

## Installation
### Prerequisites
- Python 3.12
- Linux or macOS (Windows users may need WSL)

### Install Dependencies
```sh
pip install -r requirements.txt
```

## Usage
```sh
python scanner.py
```
Follow the prompts to enter the target domain or IP.

## Example Output
- Scans the target with 100+ tools
- Uses AI to analyze risk levels
- Saves structured reports in JSON & HTML format

## Contribution
Feel free to open issues or submit pull requests to enhance the tool!

## Disclaimer
This tool is for **educational and ethical hacking purposes only**. Unauthorized scanning is illegal.

## License
MIT License
