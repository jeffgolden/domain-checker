# 🔍 Domain Intelligence Checker

> A comprehensive, cross-platform command-line tool for domain security analysis, DNS configuration auditing, and email authentication assessment.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform Support](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20FreeBSD-blue)](https://github.com/jeffgolden/domain-checker)
[![Shell](https://img.shields.io/badge/Shell-Bash-green)](https://github.com/jeffgolden/domain-checker)

## ✨ Features

- 🌍 **DNS Record Analysis** - A, AAAA, MX, and NS records.
- 🛡️ **Email Security** - SPF, DKIM, and DMARC policy analysis.
- 🌐 **SSL/TLS Certificate Monitoring** - Expiration warnings and CA details.
- 🔒 **Security Headers Assessment** - HSTS, X-Frame-Options, and X-Content-Type-Options.
- 📋 **WHOIS Intelligence** - Complete registration data, including registrant, admin, and tech contacts, and privacy protection detection.
- 🎨 **Beautiful Terminal Output** - Colored output with Unicode symbols for easy reading.
- 🖥️ **Cross-Platform** - Works on Linux, macOS, and FreeBSD.
- ⚡ **Lightweight and Fast** - Uses standard Unix tools for maximum performance.

## 📸 Sample Output

```
Analyzing domain: google.com
Generated on Fri Jun 27 21:43:53 CDT 2025 • Platform: macOS

▓▓▓ DNS RECORDS 🌐 ▓▓▓
Core DNS configuration
  ✓ A Record: 172.217.4.46
  ✓ AAAA Record: 2607:f8b0:4009:809::200e
  ✓ MX Records: 
    • 10 smtp.google.com.
  ✓ Nameservers: 
    • ns4.google.com.
    • ns2.google.com.
    • ns1.google.com.
    • ns3.google.com.

▓▓▓ DOMAIN REGISTRATION 📋 ▓▓▓
WHOIS and registration details
  ✓ Registrar: MarkMonitor Inc.
  ✓ Registration Date: 1997-09-15T04:00:00Z
  ✓ Last Updated: 2019-09-09T15:39:04Z
  ✓ Expiration Date: 2028-09-14T04:00:00Z
  ✓ Status: ACTIVE

  Registrant Information:
  →   Organization: Google LLC
  →   Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com
  →   Country: US

  Technical Contact:
  →   Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com

▓▓▓ SECURITY HEADERS 🛡️ ▓▓▓
HTTP security header analysis
  ✗ HSTS: Not enabled
  ✓ X-Frame-Options: Set
  ✗ X-Content-Type-Options: Not set

▓▓▓ SSL CERTIFICATE 🔒 ▓▓▓
TLS/SSL certificate details
  ✓ SSL Certificate: Valid
  → Issuer: Validity
  → Expires: Aug 25 08:35:29 2025 GMT
  → Days until expiry: 58 days

▓▓▓ EMAIL SECURITY 📧 ▓▓▓
SPF, DKIM, and DMARC configuration
  ✓ SPF Record: Found
  →   Policy: v=spf1 include:_spf.google.com ~all
  →   Enforcement: SoftFail (recommended)
    Includes:
      • _spf.google.com

  → DKIM Selectors: Checking common selectors...
  ✗ DKIM: No selectors found
    ⚠ Email authentication not configured

  ✓ DMARC Record: Found
  →   Policy: v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
  →   Protection Level: reject (strict)
  →   Reporting: Enabled

▓▓▓ WEBSITE STATUS 🌍 ▓▓▓
HTTP/HTTPS connectivity check
  → HTTPS Status: 301 Redirect

Analysis complete for google.com
Generated on Fri Jun 27 21:43:54 CDT 2025 • Platform: macOS
```

## 🚀 Quick Start

```bash
git clone https://github.com/jeffgolden/domain-checker.git
cd domain-checker
chmod +x domaincheck.sh
./domaincheck.sh example.com
```

## 📦 Installation

### Prerequisites

The tool relies on the following command-line utilities, which are typically pre-installed on most Unix-like systems:

- `dig` (for DNS lookups)
- `curl` (for HTTP requests)
- `whois` (for domain registration lookups)
- `openssl` (for SSL/TLS certificate analysis)

### Platform-Specific Installation

<details>
<summary><strong>🐧 Linux (Ubuntu/Debian)</strong></summary>

```bash
# Install dependencies
sudo apt update
sudo apt install dnsutils whois curl openssl

# Clone repository
git clone https://github.com/jeffgolden/domain-checker.git
cd domain-checker
chmod +x domaincheck.sh
```
</details>

<details>
<summary><strong>🍎 macOS</strong></summary>

```bash
# Dependencies usually pre-installed, or install via Homebrew
brew install bind whois curl openssl

# Clone repository  
git clone https://github.com/jeffgolden/domain-checker.git
cd domain-checker
chmod +x domaincheck.sh
```
</details>

<details>
<summary><strong>🔰 FreeBSD</strong></summary>

```bash
# Install dependencies
sudo pkg install bind-tools whois curl openssl

# Clone repository
git clone https://github.com/jeffgolden/domain-checker.git
cd domain-checker
chmod +x domaincheck.sh
```
</details>

<details>
<summary><strong>🐳 Docker</strong></summary>

```bash
# Run with Docker (no installation required)
docker run --rm -it alpine:latest sh -c "
  apk add --no-cache bind-tools whois curl openssl bash git && 
  git clone https://github.com/jeffgolden/domain-checker.git &&
  cd domain-checker && 
  chmod +x domaincheck.sh &&
  ./domaincheck.sh example.com
"
```
</details>

### Optional: System-Wide Installation

```bash
# Make available system-wide
sudo cp domaincheck.sh /usr/local/bin/domaincheck
sudo chmod +x /usr/local/bin/domaincheck

# Now run from anywhere
domaincheck example.com
```

## 💻 Usage

### Basic Usage

```bash
# Analyze a domain
./domaincheck.sh example.com

# Check dependencies
./domaincheck.sh --check-deps

# Show help
./domaincheck.sh --help

# Show version
./domaincheck.sh --version
```

### Advanced Examples

```bash
# Batch analysis
for domain in google.com microsoft.com github.com; do
    echo "=== Analyzing $domain ==="
    ./domaincheck.sh "$domain"
    echo
done

# Save results to file
./domaincheck.sh example.com > analysis_report.txt

# Remove colors for clean output
./domaincheck.sh example.com | sed 's/\x1b\[[0-9;]*m//g' > clean_report.txt

# Check SSL certificate expiry only
./domaincheck.sh example.com | grep -A 5 "SSL Certificate"

# Monitor DMARC policies
./domaincheck.sh example.com | grep -A 10 "DMARC Policy"
```

## 🔍 What It Analyzes

### 🌍 DNS Resolution
- **IPv4/IPv6 Addresses** with geolocation data
- **Name Servers** configuration  
- **Mail Exchange (MX)** records with priorities
- **Geographic Intelligence** (city, region, country, ISP)

### 🛡️ Email Security
- **SPF Records** - Sender Policy Framework validation
- **DKIM Analysis** - DomainKeys signature verification  
- **DMARC Policies** - Authentication and reporting configuration
  - Policy actions (none/quarantine/reject)
  - Enforcement percentages
  - Report destination addresses
  - Alignment settings

### 🌐 Web Services
- **HTTP/HTTPS Connectivity** testing
- **SSL/TLS Certificates** with detailed analysis:
  - Certificate authority and subject information
  - Expiration dates with warnings
  - Days remaining calculation
  - Validity verification

### 🔒 Security Headers
- **HSTS** (HTTP Strict Transport Security)
- **X-Frame-Options** (Clickjacking protection)
- **X-Content-Type-Options** (MIME sniffing protection)

### 📋 Domain Registration
- **WHOIS Data** extraction and parsing
- **Registrar Information** and status codes
- **Important Dates**:
  - Registration date
  - Last update date
  - Expiration date
- **Registrant Information**:
  - Name and Organization
  - Email address
  - Country and State/Province
- **Contact Details**:
  - Administrative contact (name & email)
  - Technical contact (name & email)
- **Privacy Protection Detection** - Identifies domains using WHOIS privacy/proxy services
- **Domain Status** codes and lock information


### Enhanced WHOIS Output Example

When analyzing a domain, the tool now provides comprehensive registration information:

```
▓▓▓ DOMAIN REGISTRATION 📋 ▓▓▓
WHOIS and registration details
  ✓ Registrar: MarkMonitor Inc.
  ✓ Registration Date: 1997-09-15
  ✓ Last Updated: 2024-09-09T15:39:04Z
  ✓ Expiration Date: 2028-09-14T04:00:00Z
  ✓ Status: ACTIVE

  Registrant Information:
  → Name: REDACTED FOR PRIVACY
  → Organization: Example Corp
  → Email: contact@example.com
  → Country: US
  → State/Province: CA

  Administrative Contact:
  → Name: Domain Administrator
  → Email: admin@example.com

  Technical Contact:
  → Name: Technical Support
  → Email: tech@example.com

  ⚠️  Note: This domain appears to use WHOIS privacy protection
```

The tool automatically detects when domains use privacy protection services and alerts you accordingly.

## 🎯 Use Cases

### 🔐 Security Assessments
- **Email Security Audits** - Verify SPF, DKIM, DMARC configuration
- **SSL Certificate Monitoring** - Track expiration dates across domains
- **Security Header Compliance** - Assess modern web security practices
- **Domain Takeover Prevention** - Verify DNS configurations

### 🔧 Operations & Monitoring  
- **Infrastructure Changes** - Verify DNS propagation after updates
- **Email Deliverability** - Troubleshoot authentication issues
- **Certificate Management** - Proactive SSL renewal alerts
- **Compliance Reporting** - Generate security posture reports

### 🚀 Development & Testing
- **Staging Environment Verification** - Ensure proper DNS setup
- **Security Configuration Testing** - Validate header implementation  
- **Third-party Integration** - Verify external service configurations
- **Email System Testing** - Validate authentication setup

## 🛠️ Technical Details

### Cross-Platform Compatibility
- **Automatic OS Detection** - Adapts to macOS, Linux, FreeBSD
- **Platform-Specific Date Parsing** - Handles BSD vs GNU date differences
- **Graceful Degradation** - Continues analysis if some checks fail
- **Timeout Handling** - Prevents hanging on unresponsive services

### Performance & Reliability
- **Connection Timeouts** - 10-second limits prevent hanging
- **Parallel Processing** - Efficient DNS query execution
- **Error Handling** - Comprehensive fallback mechanisms
- **Input Validation** - Domain format verification

### Data Sources
- **DNS Queries** - Direct authoritative lookups
- **Geolocation** - ip-api.com (free, no API key required)
- **SSL Analysis** - OpenSSL direct certificate inspection
- **WHOIS Data** - Standard protocol queries

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 Bug Reports
- Use GitHub Issues to report bugs
- Include platform information (`uname -a`)
- Provide sample domain and error output
- Test with known working domains first

### ✨ Feature Requests
- Check existing issues before creating new ones
- Explain the use case and expected behavior
- Consider implementation complexity

### 🔧 Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Test on multiple platforms if possible
4. Commit with clear messages (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### 🧪 Testing
```bash
# Test basic functionality
./domaincheck.sh example.com

# Test error handling
./domaincheck.sh invalid-domain-name

# Test dependencies
./domaincheck.sh --check-deps

# Cross-platform testing appreciated!
```

## 📋 Roadmap

- [ ] **JSON Output Format** - Machine-readable results
- [ ] **Bulk Domain Processing** - File input support
- [ ] **Additional DNS Records** - CAA, TLSA, SRV analysis
- [ ] **Custom Geolocation Providers** - Alternative API support
- [ ] **Performance Benchmarking** - Speed optimization
- [ ] **Configuration File** - Customizable check settings
- [ ] **Plugin System** - Extensible analysis modules

## 🚨 Legal & Ethical Use

### ✅ Acceptable Use
- Security assessment of owned/managed domains
- Due diligence research on business partners
- Educational and training purposes  
- Troubleshooting legitimate technical issues

### ❌ Prohibited Use
- Unauthorized reconnaissance or scanning
- Rate limiting abuse or denial of service
- Privacy violations or data harvesting
- Any activity violating computer access laws

### 🔒 Privacy & Data
- Tool queries public DNS records only
- Uses publicly available WHOIS databases
- Makes standard HTTP requests (no cookies/tracking)
- Geolocation from public APIs (no user data stored)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with standard Unix tools and open protocols
- Inspired by the need for comprehensive domain intelligence
- Community feedback and contributions welcome
- Special thanks to the open source security community

## 📞 Support

- **Documentation**: See this README and inline help (`--help`)
- **Issues**: [GitHub Issues](https://github.com/jeffgolden/domain-checker/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jeffgolden/domain-checker/discussions)

---


