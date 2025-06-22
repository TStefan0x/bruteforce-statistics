# bruteforce-statistics

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A lightweight Flask dashboard for real-time monitoring of SSH login attempts. It parses `/var/log/auth.log`, excludes known IPs, and renders:

- **Top targeted usernames**
- **Top attacking IP addresses**
- **Hourly failed login trends**

Auto-refreshes every 3 seconds with minimal CPU overhead (<5%). Ideal for SOC teams to spot suspicious activity and harden security policies.

---

## Features

- **Live Charts**: Chart.js with WebSockets for seamless updates.
- **Rate Limiting**: Prevents self-induced overload via Flask-Limiter.
- **Dark/Light Mode**: Toggle theme with one click.
- **Low Resource**: Uses <5% CPU during operation.
- **Portable**: Runs on any Linux server with Python 3.

---

## Prerequisites

- Python 3.7 or newer
- Read access to `/var/log/auth.log` (or adjust the path in `main.py`)
- `pip` for installing dependencies

---

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/youruser/bruteforce-statistics.git
   cd bruteforce-statistics
   pip install -r requierments.txt
   (edit main.py if log path is not default)
   python3 main.py
2. **Connect to dashboard**
   ```bash
   Running on http://127.0.0.1:5000
   OR
   Local ip using 192.168.x.x:5000
