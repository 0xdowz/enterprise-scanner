# AWS Enterprise Scanner

A next-generation web security scanner with advanced threat detection capabilities, AI-powered anomaly detection, and comprehensive vulnerability assessment features.

![carbon](https://github.com/user-attachments/assets/fd37c388-faf7-479c-8314-9b8dad409365)


## Features

- **Intelligent Crawling**: Automatically discovers and maps web application endpoints
- **Advanced Fuzzing**: Tests endpoints for various vulnerabilities including SSTI and deserialization
- **AI-Powered Anomaly Detection**: Uses machine learning to identify suspicious behavior patterns
- **Threat Intelligence Integration**: Leverages up-to-date threat feeds for enhanced detection
- **Multiple Scanning Modes**: Full scan, reconnaissance only, or targeted payload testing
- **Evasion Techniques**: Optional stealth mode with randomized headers and behavior
- **Tor Network Support**: Anonymous scanning capability through Tor network
- **Flexible Reporting**: Export results in HTML, JSON, Markdown, or SARIF formats

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (for cloning the repository)
- Windows, Linux, or macOS

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/enterprise-scanner.git
cd enterprise-scanner
```

2. Create and activate a virtual environment (recommended):
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

4. Verify the installation:
```bash
python scanner.py --version
```

## Usage

### Windows
Run using the provided batch file:
```bash
awsscn.bat <target_url> [options]
```

### Linux/macOS/Windows
Run directly using Python:
```bash
python scanner.py <target_url> [options]
```

### Command Line Options

- `<target_url>`: Target URL to scan (required)
- `-f, --format`: Report format [html, json, md, sarif] (default: html)
- `-m, --mode`: Scan mode [full, recon, quick] (default: full)
- `-e, --evasion`: Enable evasion techniques
- `-t, --tor`: Use Tor network for anonymous scanning
- `-r, --rate`: Rate limit for requests per second (default: 50)
- `-o, --output`: Custom output directory for reports
- `-v, --verbose`: Enable verbose output
- `--version`: Show version information

### Examples

1. Basic scan with default options:
```bash
python scanner.py https://example.com
```

2. Full scan with evasion and JSON report:
```bash
python scanner.py https://example.com -e -f json
```

3. Quick scan through Tor network:
```bash
python scanner.py https://example.com -t -m quick
```

## Features in Detail

### 1. Reconnaissance
- DNS enumeration and subdomain discovery
- Technology stack detection
- Security header analysis
- SSL/TLS assessment

### 2. Discovery
- Intelligent endpoint crawling
- Asset and resource mapping
- API endpoint detection (REST, GraphQL)
- Authentication mechanism identification

### 3. Vulnerability Testing
- Server-Side Template Injection (SSTI)
- Insecure Deserialization
- GraphQL vulnerabilities
- Binary file analysis
- Access control testing
- Error handling assessment

### 4. Reporting
- Detailed vulnerability descriptions
- Risk severity categorization
- Remediation recommendations
- Machine-readable export formats

## Security Considerations

- Always obtain proper authorization before scanning any systems
- Use the tool responsibly and ethically
- Follow local laws and regulations regarding security testing
- Consider using the Tor option for enhanced anonymity
- Regularly update the tool and its dependencies

## Contributing

We welcome contributions! Here's how you can help:

1. **Fork the Repository**
   - Create your feature branch (`git checkout -b feature/AmazingFeature`)
   - Commit your changes (`git commit -m 'Add some AmazingFeature'`)
   - Push to the branch (`git push origin feature/AmazingFeature`)
   - Open a Pull Request

2. **Report Issues**
   - Use the GitHub issue tracker
   - Include detailed steps to reproduce
   - Attach relevant logs and screenshots

3. **Improve Documentation**
   - Fix typos and clarify existing docs
   - Add examples and use cases
   - Translate documentation

4. **Code Style**
   - Follow PEP 8 guidelines
   - Add docstrings and comments
   - Write unit tests for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for authorized security testing only. The authors are not responsible for any misuse or damage caused by this program. Unauthorized scanning of systems you don't own or have explicit permission to test is illegal and unethical.

## Support

For support, feature requests, or bug reports, please open an issue on GitHub.
