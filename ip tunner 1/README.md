# Network Diagnostic Tool

A web-based network diagnostic tool that allows users to perform various network tests on IPv4 and IPv6 addresses.

## Features

- ✅ Ping test with latency statistics
- ✅ MTR (My Traceroute) report
- ✅ Traceroute analysis
- ✅ Port scanning
- ✅ Basic firewall detection

## Prerequisites

- Python 3.7 or higher
- MTR (My Traceroute) installed on your system
- Administrator/root privileges (for some network operations)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd network-diagnostic-tool
```

2. Install the required Python packages:
```bash
pip install -r requirements.txt
```

3. Install MTR (if not already installed):
- On Windows: Download and install from [MTR website](https://github.com/traviscross/mtr)
- On Linux: `sudo apt-get install mtr` (Ubuntu/Debian) or `sudo yum install mtr` (RHEL/CentOS)
- On macOS: `brew install mtr`

## Usage

1. Start the Flask application:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Enter an IPv4 or IPv6 address in the input field and click "Run Diagnostics"

## Security Notes

- This tool requires network access and may be blocked by firewalls
- Some operations (like port scanning) may be restricted by your network administrator
- Use responsibly and only on networks you have permission to test

## License

MIT License 