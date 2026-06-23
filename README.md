# Phishing URL Detector

A lightweight Python-based phishing detection tool that analyzes URLs using heuristic feature extraction and risk scoring. The detector identifies common phishing indicators such as suspicious keywords, spoofed brand names, malicious top-level domains (TLDs), excessive subdomains, raw IP addresses, and other URL characteristics frequently used in phishing attacks.

## Features

* URL feature extraction
* Heuristic phishing risk scoring
* Detection of suspicious keywords
* Detection of brand impersonation in subdomains
* Suspicious TLD identification
* IP address URL detection
* Domain entropy analysis
* Batch URL analysis mode
* Human-readable risk explanations
* No external dependencies required

---

## How It Works

The detector extracts various characteristics from a URL and assigns risk points based on known phishing techniques.

### Features Analyzed

| Feature              | Description                                                                     |
| -------------------- | ------------------------------------------------------------------------------- |
| HTTPS Usage          | Checks if the URL uses HTTPS                                                    |
| IP Address Detection | Flags URLs that use raw IP addresses instead of domains                         |
| URL Length           | Detects unusually long URLs                                                     |
| Subdomain Depth      | Identifies excessive subdomain nesting                                          |
| Brand Spoofing       | Detects trusted brand names hidden in subdomains                                |
| Suspicious Keywords  | Looks for phishing-related terms such as login, verify, account, password, etc. |
| TLD Analysis         | Flags commonly abused top-level domains                                         |
| Domain Entropy       | Measures randomness in domain names                                             |
| Special Characters   | Detects potentially suspicious URL structures                                   |
| Digit Count          | Flags domains with excessive numeric characters                                 |

---

## Risk Scoring

The detector generates a score between **0 and 100**.

### Classification Thresholds

| Score  | Classification     |
| ------ | ------------------ |
| 0–34   | 🟢 Likely Safe     |
| 35–59  | 🟡 Suspicious      |
| 60–100 | 🔴 Likely Phishing |

The score is accompanied by explanations showing which phishing indicators contributed to the result.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/phishing-url-detector.git
cd phishing-url-detector
```

No third-party libraries are required.

Requirements:

* Python 3.8+

---

## Usage

### Analyze a Single URL

```bash
python phishing_detector.py https://example.com
```

Example:

```bash
python phishing_detector.py https://paypal.com-secure-login.xyz/signin
```

---

### Analyze Multiple URLs

```bash
python phishing_detector.py url1 url2 url3
```

Example:

```bash
python phishing_detector.py \
https://google.com \
https://paypal.com-secure-login.xyz
```

---

### Batch Mode

```bash
python phishing_detector.py --batch url1 url2 url3
```

Example:

```bash
python phishing_detector.py --batch \
https://google.com \
https://paypal.com-secure-login.xyz \
http://amazon-account-verify.tk
```

---

## Example Output

```text
=======================================================
  URL: https://paypal.com-secure-login.xyz/signin
=======================================================

  🔴 Verdict : LIKELY PHISHING
      Risk Score : 70/100

  Features Extracted:
    HTTPS         : Yes
    IP Address    : No
    TLD           : .xyz
    Subdomain Depth: 0
    URL Length    : 42
    Domain Entropy: 3.84
    @ Symbol      : No

  ⚠ Red Flags:
    • Phishing keywords found: signin
    • Suspicious TLD: .xyz
```

---

## Demo Mode

Running the script without arguments launches a built-in demonstration using several sample URLs.

```bash
python phishing_detector.py
```

The demo showcases both safe and potentially malicious URLs to demonstrate scoring behavior.

---

## Project Structure

```text
phishing_detector.py
```

### Main Components

* `extract_features()` – Extracts URL characteristics.
* `score_url()` – Calculates phishing risk score.
* `classify()` – Determines final verdict.
* `analyze()` – Displays detailed analysis.
* `batch_analyze()` – Processes multiple URLs simultaneously.
* `shannon_entropy()` – Measures domain randomness.

---

## Limitations

This project uses heuristic analysis and does not:

* Query threat intelligence databases
* Verify domain reputation
* Perform DNS lookups
* Use machine learning models
* Detect every phishing attempt

It should be considered a supplemental analysis tool rather than a complete phishing detection solution.

---

## Future Improvements

Potential enhancements include:

* Machine learning classification
* WHOIS age analysis
* DNS reputation checks
* Threat intelligence API integration
* Browser extension support
* GUI dashboard
* Real-time URL monitoring
* Exportable reports

---

## Educational Purpose

This project was created as a cybersecurity learning exercise to demonstrate how phishing URLs can be identified using feature extraction and heuristic analysis techniques.

## License

MIT License
