# AWS Enterprise Scanner 🚀🔒

A next-generation web security scanner with advanced threat detection, AI-powered anomaly detection, and comprehensive vulnerability assessments. Designed for security professionals, this tool automates the discovery, mapping, and testing of web application endpoints with precision and ease. 💻✨

---
![carbon](https://github.com/user-attachments/assets/abc94a10-f469-4400-a0f4-38bbd138b9f4)


##Overview 🌐🔍

AWS Enterprise Scanner automates the discovery, mapping, and testing of web application endpoints. Leveraging AI and threat intelligence, it identifies vulnerabilities such as Server-Side Template Injection (SSTI) and insecure deserialization. Whether you need a comprehensive audit or a quick reconnaissance, this tool adapts to your needs with style and speed. ⚡🔥

---

##Features ⭐

- **Intelligent Crawling**: Automatically discovers and maps web application endpoints. 🤖🕸️
- **Advanced Fuzzing**: Tests endpoints for vulnerabilities like SSTI and insecure deserialization. 🔍💥
- **AI-Powered Anomaly Detection**: Uses machine learning to identify suspicious behavior and potential threats. 🤖🚨
- **Threat Intelligence Integration**: Leverages up-to-date threat feeds for enhanced vulnerability detection. 📡🔗
- **Multiple Scanning Modes**: Offers full scans, reconnaissance only, or targeted payload testing. 🎯🔄
- **Evasion Techniques**: Optional stealth mode with randomized headers and behavior to avoid detection. 🕵️‍♂️💨
- **Tor Network Support**: Enables anonymous scanning via the Tor network for added privacy. 🕸️🎭
- **Flexible Reporting**: Export results in formats such as HTML, JSON, Markdown, or SARIF. 📊📝

---

##Prerequisites ⚙️

- **Python**: Version 3.8 or higher is required. 🐍
- **pip**: The package installer for Python. 📦
- **Git**: For cloning the repository. 🌲
- **Operating Systems**: Compatible with Windows, Linux, and macOS. 💻🖥️

---

##Installation 🛠️

Follow these steps to install and set up AWS Enterprise Scanner:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/0xdowz/enterprise-scanner.git
   cd enterprise-scanner
   ```
   🌟

2. **Create and Activate a Virtual Environment** (Recommended):
   - **Windows**:
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   - **Linux/macOS**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   🔄

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   📦

4. **Verify the Installation**:
   ```bash
   python scanner.py --version
   ```
   ✅

---

## Usage 🚀

###Running the Scanner

Execute AWS Enterprise Scanner using the provided scripts or directly via Python:

- **Windows (Batch File)**:
  ```bash
  awsscn.bat <target_url> [options]
  ```
  📄

- **Linux/macOS/Windows (Python)**:
  ```bash
  python scanner.py <target_url> [options]
  ```
  🖥️

### Command Line Options ⚙️

- **`<target_url>`**: Target URL to scan (**required**) 🌐
- **`-f, --format`**: Report format `[html, json, md, sarif]` (default: `html`) 📊
- **`-m, --mode`**: Scan mode `[full, recon, quick]` (default: `full`) 🚀
- **`-e, --evasion`**: Enable evasion techniques to bypass security mechanisms 🕵️‍♀️
- **`-t, --tor`**: Use the Tor network for anonymous scanning 🎭
- **`-r, --rate`**: Rate limit for requests per second (default: `50`) ⏩
- **`-o, --output`**: Specify a custom output directory for reports 📁
- **`-v, --verbose`**: Enable verbose output for detailed logs 📜
- **`--version`**: Display version information 🔢

### Examples 🔧

1. **Basic Scan with Default Options**:
   ```bash
   python scanner.py https://example.com
   ```
   🔍

2. **Full Scan with Evasion and JSON Report**:
   ```bash
   python scanner.py https://example.com -e -f json
   ```
   🕵️‍♂️➡️📄

3. **Quick Scan Through Tor Network**:
   ```bash
   python scanner.py https://example.com -t -m quick
   ```
   🎭⚡

---

## Detailed Feature Descriptions 📖

### 1. Reconnaissance 🔍

- **DNS Enumeration & Subdomain Discovery**: Automatically locate associated domains. 🌐🔎
- **Technology Stack Detection**: Identify frameworks, libraries, and CMSs in use. 🏗️📚
- **Security Header Analysis**: Evaluate HTTP security headers for misconfigurations. 🛡️
- **SSL/TLS Assessment**: Check certificate validity and encryption strength. 🔐

### 2. Discovery 🗺️

- **Intelligent Endpoint Crawling**: Uncover hidden and unlinked endpoints. 🚀🔍
- **Asset & Resource Mapping**: Build a comprehensive map of your assets and resources. 🗺️💡
- **API Endpoint Detection**: Supports REST, GraphQL, and other API types. 🔗
- **Authentication Mechanism Identification**: Determine the security measures in place. 🔑

### 3. Vulnerability Testing 💥

- **Server-Side Template Injection (SSTI)**: Detect potential injection flaws. 🔥
- **Insecure Deserialization**: Identify risks from untrusted data deserialization. ⚠️
- **GraphQL Vulnerabilities**: Assess common weaknesses in GraphQL implementations. 📉
- **Binary File Analysis**: Inspect binary files for hidden vulnerabilities. 🔍📦
- **Access Control Testing**: Ensure proper enforcement of access restrictions. 🚪🔒
- **Error Handling Assessment**: Analyze error messages to prevent information leakage. 📝

### 4. Reporting 📝

- **Detailed Vulnerability Descriptions**: Clear explanations for each identified issue. 📝🔍
- **Risk Severity Categorization**: Prioritize vulnerabilities based on potential impact. ⚖️
- **Remediation Recommendations**: Get actionable advice to resolve issues. 💡🔧
- **Export Formats**: Choose from HTML, JSON, Markdown, or SARIF for your reports. 📊💻

---

## Security Considerations 🔒🚨

- **Authorization**: Always obtain explicit permission before scanning any system. ✅
- **Responsible Use**: Use this tool ethically and in compliance with local laws. ⚖️
- **Anonymity**: Consider using the Tor option for enhanced privacy. 🎭
- **Updates**: Regularly update the tool and its dependencies to stay ahead of emerging threats. 🔄

---

## Contributing 🤝💬

We welcome contributions to improve AWS Enterprise Scanner! Here’s how you can help:

1. **Fork the Repository**:
   - Create a feature branch:
     ```bash
     git checkout -b feature/AmazingFeature
     ```
   - Commit your changes with clear messages:
     ```bash
     git commit -m 'Add AmazingFeature'
     ```
   - Push your branch:
     ```bash
     git push origin feature/AmazingFeature
     ```
   - Open a Pull Request for review. 🔀

2. **Report Issues**:
   - Use the GitHub issue tracker to report bugs or request features. 🐞🚀
   - Provide detailed reproduction steps, logs, and screenshots when applicable. 📸

3. **Improve Documentation**:
   - Enhance existing documentation with examples and use cases. 📚
   - Translate documentation to assist non-English speakers. 🌍

4. **Code Quality**:
   - Follow PEP 8 guidelines. 📏
   - Include docstrings, inline comments, and write unit tests for new features. 🧪

---

## License 📄

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 📜

---

## Disclaimer ⚠️

This tool is intended for authorized security testing only. The authors are not responsible for any misuse or damage caused by this program. Unauthorized scanning without explicit permission is illegal and unethical. 🚫

---

## Support & Feedback 📣

For support, feature requests, or bug reports, please open an issue on our [GitHub repository](https://github.com/0xdowz/enterprise-scanner/issues). Your feedback is essential to help us improve the tool! 🙌💬
