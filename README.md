# AWS Enterprise Scanner

A next-generation web security scanner with advanced threat detection capabilities, AI-powered anomaly detection, and comprehensive vulnerability assessment features.

## Features

- **Intelligent Crawling**: Automatically discovers and maps web application endpoints
- **Advanced Fuzzing**: Tests endpoints for various vulnerabilities
- **AI-Powered Anomaly Detection**: Uses machine learning to identify suspicious behavior
- **Threat Intelligence Integration**: Leverages up-to-date threat feeds
- **Multiple Scanning Modes**: Full scan, reconnaissance only, or payload testing
- **Evasion Techniques**: Optional stealth mode for avoiding detection
- **Tor Network Support**: Anonymous scanning capability
- **Flexible Reporting**: Export results in HTML, JSON, Markdown, or SARIF formats

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/enterprise-scanner.git
cd enterprise-scanner
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

The scanner can be run using the provided batch file on Windows:
```bash
awsscn.bat <target_url> [options]
```

Or directly using Python:
```bash
python scanner.py <target_url> [options]
```

### Command Line Options

- `<target_url>`: The URL of the target to scan (required)
- `-f, --format`: Report output format (html, json, md, sarif) [default: html]
- `-e, --evasion`: Enable evasion techniques
- `-t, --tor`: Use Tor network for scanning

### Examples

1. Basic scan with default options:
```bash
awsscn.bat https://example.com
```

2. Full scan with evasion and JSON report:
```bash
awsscn.bat https://example.com -e -f json
```

3. Scan using Tor network:
```bash
awsscn.bat https://example.com -t
```

## Scanning Phases

1. **Reconnaissance**: 
   - DNS enumeration
   - Subdomain discovery

2. **Discovery**:
   - Endpoint crawling
   - Asset mapping

3. **Fuzzing**:
   - Parameter testing
   - CORS checks
   - GraphQL endpoint testing
   - Deserialization checks

4. **Reporting**:
   - Vulnerability assessment
   - Risk categorization
   - Remediation recommendations

## Security Considerations

- Always obtain proper authorization before scanning any systems
- Use the tool responsibly and ethically
- Follow local laws and regulations regarding security testing
- Consider using the Tor option for enhanced anonymity

## Disclaimer

This tool is intended for authorized security testing only. Unauthorized scanning of systems you don't own or have explicit permission to test is illegal and unethical.

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit pull requests.