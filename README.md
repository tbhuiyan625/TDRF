# 🔒 TDRF - Threat Detection & Response Framework

<div align="center">

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![GitHub Stars](https://img.shields.io/github/stars/tbhuiyan625/TDRF?style=for-the-badge)
![GitHub Forks](https://img.shields.io/github/forks/tbhuiyan625/TDRF?style=for-the-badge)

<h3>🛡️ Professional Security Analysis & Threat Detection Tool</h3>
<p>Enterprise-grade Python framework for cybersecurity professionals</p>

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

<img src="https://raw.githubusercontent.com/tbhuiyan625/TDRF/main/screenshots/banner.png" alt="TDRF Banner" width="800" />

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Modules](#-modules)
- [Configuration](#-configuration)
- [Screenshots](#-screenshots)
- [Security Notice](#-security-notice)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## 🎯 Overview

**TDRF (Threat Detection & Response Framework)** is a comprehensive Python-based security framework designed for threat detection, network reconnaissance, and incident response. Built with enterprise security operations in mind, it provides real-time threat analysis, automated detection, and professional reporting capabilities.

### 🏆 **Why TDRF?**

- ⚡ **Fast & Efficient**: Multi-threaded architecture for rapid scanning
- 🎯 **Accurate Detection**: Advanced pattern matching and correlation
- 📊 **Professional Reports**: HTML, PDF, and JSON export capabilities
- 🖥️ **Dual Interface**: Both CLI and GUI for different use cases
- 🔧 **Modular Design**: Easy to extend and customize
- 📚 **Well Documented**: Comprehensive documentation and examples

---

## ✨ Key Features

### 🔍 **Log Analysis & Threat Detection**
- ✅ Real-time Windows Event Log monitoring
- ✅ Brute force attack detection (configurable thresholds)
- ✅ Failed login pattern analysis with statistical modeling
- ✅ Custom log parsing (syslog, Apache, SSH, IIS)
- ✅ Regex-based pattern matching
- ✅ Automatic alert generation

### 🌐 **Network Port Scanner**
- ✅ Multi-threaded concurrent scanning
- ✅ Service banner grabbing and version detection
- ✅ 1000+ common service fingerprints
- ✅ Custom port range scanning (1-65535)
- ✅ TCP connect and SYN scanning
- ✅ Vulnerability risk assessment

### 🧩 **Event Correlation Engine**
- ✅ Cross-source data correlation
- ✅ Advanced pattern recognition algorithms
- ✅ Automated threat severity classification
- ✅ Historical trend analysis
- ✅ Anomaly detection using statistical methods
- ✅ Real-time alert generation

### 📊 **Reporting & Visualization**
- ✅ Interactive HTML dashboards
- ✅ Professional PDF executive reports
- ✅ JSON data export for SIEM integration
- ✅ Real-time threat statistics
- ✅ Customizable report templates
- ✅ Executive summary generation

### 🖥️ **User Interfaces**
- ✅ Full-featured CLI with colored output
- ✅ Modern GUI built with tkinter
- ✅ Interactive menus and wizards
- ✅ Progress indicators and status updates

---

## 🏗️ Architecture

```
TDRF/
├── 📁 analyzers/          # Log analysis modules
│   ├── windows_events.py  # Windows Event Log parser
│   ├── syslog_parser.py   # Syslog analyzer
│   └── pattern_matcher.py # Pattern detection engine
│
├── 📁 scanners/           # Network scanning modules
│   ├── port_scanner.py    # Multi-threaded port scanner
│   ├── service_detect.py  # Service fingerprinting
│   └── banner_grabber.py  # Banner grabbing utility
│
├── 📁 correlation/        # Event correlation
│   ├── correlator.py      # Main correlation engine
│   ├── rules_engine.py    # Detection rules
│   └── threat_scoring.py  # Threat severity calculator
│
├── 📁 reporting/          # Report generation
│   ├── html_generator.py  # HTML report builder
│   ├── pdf_generator.py   # PDF export
│   └── json_exporter.py   # JSON data export
│
├── 📁 interfaces/         # User interfaces
│   ├── cli.py             # Command-line interface
│   └── gui.py             # Graphical interface
│
├── 📁 core/               # Core functionality
│   ├── config.py          # Configuration management
│   ├── database.py        # Data persistence
│   └── logger.py          # Logging system
│
└── 📁 utils/              # Utility functions
    ├── network.py         # Network utilities
    ├── file_ops.py        # File operations
    └── validators.py      # Input validation
```

---

## 🚀 Installation

### **Prerequisites**
- **Python 3.8+** ([Download](https://python.org))
- **Git** ([Download](https://git-scm.com/))
- **Windows 10/11** (for Event Log features) or **Linux**
- **Administrator/Root privileges** (for network scanning)

### **Quick Install**

```bash
# Clone the repository
git clone https://github.com/tbhuiyan625/TDRF.git
cd TDRF

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m tdrf --version
```

### **Install from PyPI** *(Coming Soon)*

```bash
pip install tdrf
```

### **Docker Installation** *(Coming Soon)*

```bash
docker pull tbhuiyan625/tdrf:latest
docker run -it tdrf
```

---

## ⚡ Quick Start

### **1. CLI Mode**

```bash
# Start interactive CLI
python -m tdrf --cli

# Quick port scan
python -m tdrf --scan 192.168.1.1 --ports 1-1000

# Analyze system logs
python -m tdrf --analyze-logs

# Generate report
python -m tdrf --report html
```

### **2. GUI Mode**

```bash
# Launch graphical interface
python -m tdrf --gui
```

### **3. Python API**

```python
from tdrf import TDRF

# Initialize framework
tdrf = TDRF()

# Perform port scan
results = tdrf.scan_ports('192.168.1.1', ports=[80, 443, 8080])

# Analyze logs
threats = tdrf.analyze_logs('/var/log/auth.log')

# Generate report
tdrf.generate_report(format='html', output='security_report.html')
```

---

## 📖 Usage Examples

### **Example 1: Detect Brute Force Attacks**

```bash
# CLI
python -m tdrf --cli
> Select [1] Log Analysis
> Select [3] Detect Brute Force Attempts
```

**Output:**
```
[HIGH SEVERITY] Brute Force Attack Detected!
Source: 192.168.1.50
Attempts: 15 failed logins in 3 minutes
Action Required: Block IP and investigate
```

### **Example 2: Network Reconnaissance**

```bash
# Quick scan of common ports
python -m tdrf --scan 192.168.1.100 --ports 80,443,22,3389
```

**Output:**
```
[+] Open: 22/tcp  - SSH-2.0-OpenSSH_8.2
[+] Open: 80/tcp  - Apache/2.4.41
[+] Open: 443/tcp - nginx/1.18.0
[!] HIGH RISK: Port 3389 (RDP) exposed
```

### **Example 3: Generate Security Report**

```python
from tdrf.reporting import ReportGenerator

report = ReportGenerator()
report.add_scan_results(scan_data)
report.add_log_analysis(log_data)
report.generate('security_audit_2024.html')
```

### **Example 4: Event Correlation**

```python
from tdrf.correlation import EventCorrelator

correlator = EventCorrelator()
correlator.load_events(events)
threats = correlator.correlate()

for threat in threats:
    print(f"[{threat.severity}] {threat.description}")
```

---

## 🛠️ Modules

### **1. Log Analyzer (`analyzers/`)**

Analyzes system and application logs for security events.

**Capabilities:**
- Windows Event Log parsing (Event IDs 4625, 4624, 4720, etc.)
- Syslog analysis (auth.log, messages, secure)
- Apache/Nginx access log analysis
- Custom regex pattern matching
- Real-time log monitoring

**API:**
```python
from tdrf.analyzers import LogAnalyzer

analyzer = LogAnalyzer()
threats = analyzer.analyze_windows_events(days=7)
brute_force = analyzer.detect_brute_force(threshold=5, window_minutes=5)
```

### **2. Port Scanner (`scanners/`)**

Network reconnaissance and service identification.

**Capabilities:**
- TCP connect scanning
- SYN stealth scanning (requires root)
- Service version detection
- Banner grabbing
- OS fingerprinting
- Vulnerability assessment

**API:**
```python
from tdrf.scanners import PortScanner

scanner = PortScanner()
results = scanner.scan('192.168.1.1', ports=range(1, 1001), threads=100)
services = scanner.identify_services(results)
```

### **3. Event Correlator (`correlation/`)**

Correlates events from multiple sources to identify threats.

**Capabilities:**
- Multi-source data aggregation
- Pattern-based correlation rules
- Statistical anomaly detection
- Threat severity scoring
- Timeline reconstruction

**API:**
```python
from tdrf.correlation import EventCorrelator

correlator = EventCorrelator()
correlator.add_events(log_events)
correlator.add_events(network_events)
threats = correlator.analyze()
```

### **4. Report Generator (`reporting/`)**

Creates professional security reports in multiple formats.

**Capabilities:**
- HTML reports with CSS/JS
- PDF executive summaries
- JSON data export
- Charts and graphs
- Customizable templates

**API:**
```python
from tdrf.reporting import ReportGenerator

report = ReportGenerator()
report.add_section('Executive Summary', summary_data)
report.add_section('Findings', findings)
report.save('report.html')
```

---

## ⚙️ Configuration

### **Configuration File: `config/settings.json`**

```json
{
  "scanning": {
    "timeout_seconds": 2,
    "max_threads": 100,
    "default_ports": [21, 22, 23, 25, 80, 443, 3389]
  },
  "detection": {
    "brute_force_threshold": 5,
    "brute_force_window_minutes": 5,
    "failed_login_threshold": 3
  },
  "reporting": {
    "default_format": "html",
    "output_directory": "reports",
    "include_recommendations": true
  },
  "alerting": {
    "enabled": false,
    "email": "security@example.com",
    "smtp_server": "smtp.gmail.com"
  }
}
```

### **Environment Variables**

```bash
# Set custom config path
export TDRF_CONFIG=/path/to/config.json

# Enable debug mode
export TDRF_DEBUG=1

# Set log level
export TDRF_LOG_LEVEL=DEBUG
```

---

## 📸 Screenshots

### CLI Interface
<img src="https://raw.githubusercontent.com/tbhuiyan625/TDRF/main/screenshots/cli_interface.png" alt="CLI Interface" width="800" />

### GUI Dashboard
<img src="https://raw.githubusercontent.com/tbhuiyan625/TDRF/main/screenshots/gui_dashboard.png" alt="GUI Dashboard" width="800" />

### Security Report
<img src="https://raw.githubusercontent.com/tbhuiyan625/TDRF/main/screenshots/html_report.png" alt="HTML Report" width="800" />

### Port Scan Results
<img src="https://raw.githubusercontent.com/tbhuiyan625/TDRF/main/screenshots/port_scan.png" alt="Port Scan" width="800" />

---

## 🔐 Security Notice

### **⚠️ LEGAL DISCLAIMER**

This tool is intended for **authorized security testing and educational purposes only**.

**YOU MUST:**
- ✅ Only scan systems you own or have explicit written permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Use responsibly and ethically
- ✅ Follow responsible disclosure practices

**YOU MUST NOT:**
- ❌ Scan networks without authorization
- ❌ Use for malicious purposes
- ❌ Violate computer fraud and abuse laws
- ❌ Access systems without permission

**Potential Legal Issues:**
- Unauthorized port scanning may be illegal in your jurisdiction
- Some organizations consider scanning an attack
- Penalties may include fines and imprisonment

**Users assume all responsibility for compliance with applicable laws.**

---

## 🗺️ Roadmap

### **Version 1.1 (Q1 2025)**
- [ ] Machine learning-based anomaly detection
- [ ] Support for Linux/macOS Event Logs
- [ ] REST API for remote management
- [ ] WebSocket real-time updates
- [ ] Plugin architecture

### **Version 1.2 (Q2 2025)**
- [ ] Integration with Splunk/ELK/SIEM
- [ ] Automated incident response playbooks
- [ ] Email/SMS/Slack alerting
- [ ] Docker containerization
- [ ] Kubernetes deployment

### **Version 2.0 (Q3 2025)**
- [ ] Distributed scanning capabilities
- [ ] Cloud deployment (AWS/Azure/GCP)
- [ ] Threat intelligence feed integration
- [ ] Advanced ML threat classification
- [ ] Mobile app for alerts

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md).

### **How to Contribute**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### **Development Setup**

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/TDRF.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Check code style
flake8 tdrf/
black tdrf/
```

### **Code of Conduct**

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License - Free for commercial and personal use
```

---

## 👤 Author

**Tahmid Bhuiyan**

- 🔗 **GitHub**: [@tbhuiyan625](https://github.com/tbhuiyan625)
- 💼 **LinkedIn**: [Connect with me](https://linkedin.com/in/tbhuiyan625)
- 📧 **Email**: tbhuiyan625@gmail.com
- 🌐 **Portfolio**: [tbhuiyan625.github.io](https://tbhuiyan625.github.io/Portfolio/)

### **Skills Demonstrated**

This project showcases expertise in:

- ✅ Python Development (OOP, threading, networking)
- ✅ Cybersecurity & Threat Detection
- ✅ Network Programming & Protocols
- ✅ Windows API & Event Logs
- ✅ Data Analysis & Pattern Recognition
- ✅ Software Architecture & Design
- ✅ GUI Development (tkinter)
- ✅ Report Generation & Visualization
- ✅ Git & Version Control
- ✅ Technical Documentation

---

## 🙏 Acknowledgments

- **Colorama** - Cross-platform colored terminal text
- **Python Community** - Excellent documentation and support
- **Security Researchers** - Inspiration and methodologies
- **Open Source Contributors** - Making security tools accessible

---

## 📞 Support

### **Getting Help**

- 📖 **Documentation**: [Read the Docs](https://tdrf.readthedocs.io)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/tbhuiyan625/TDRF/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/tbhuiyan625/TDRF/discussions)
- 📧 **Email**: tbhuiyan625@gmail.com

### **Frequently Asked Questions**

**Q: Do I need administrator privileges?**
A: Yes, for Windows Event Log access and network scanning below port 1024.

**Q: Does this work on Linux?**
A: Yes, but Windows Event Log features require Windows. Syslog analysis works on all platforms.

**Q: Can I integrate this with my SIEM?**
A: Yes, via JSON export or the REST API (coming in v1.1).

**Q: Is this safe to use on production systems?**
A: Only with proper authorization and during maintenance windows.

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=tbhuiyan625/TDRF&type=Date)](https://star-history.com/#tbhuiyan625/TDRF&Date)

---

## 📊 Statistics

![GitHub repo size](https://img.shields.io/github/repo-size/tbhuiyan625/TDRF?style=flat-square)
![GitHub code size](https://img.shields.io/github/languages/code-size/tbhuiyan625/TDRF?style=flat-square)
![GitHub last commit](https://img.shields.io/github/last-commit/tbhuiyan625/TDRF?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/tbhuiyan625/TDRF?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/tbhuiyan625/TDRF?style=flat-square)

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

⭐ **Star this repo if you find it useful!** ⭐

[Report Bug](https://github.com/tbhuiyan625/TDRF/issues) · [Request Feature](https://github.com/tbhuiyan625/TDRF/issues) · [Documentation](https://github.com/tbhuiyan625/TDRF/wiki)

</div>

---

**Last Updated**: December 11, 2024  
**Version**: 1.0.0  
**Status**: ✅ Active Development
