# MayXSS - XSS Vulnerability Scanner

MayXSS is an advanced XSS vulnerability scanner developed by AIwolfie (Mayank Malaviya). It utilizes threading, automation, and AI-based payload generation to test for reflected, stored, and DOM-based XSS vulnerabilities.

---

## Features
- **AI-Powered Payloads:** Generate custom payloads using GPT-2 for enhanced coverage.
- **Multi-Type Scanning:** Supports reflected, stored, and DOM-based XSS detection.
- **Threaded Execution:** Uses multithreading for faster vulnerability scans.
- **Customizable Requests:** Add custom headers, proxies, and delays.
- **Detailed Reports:** Outputs results in HTML format with visual charts.
- **Browser Automation:** Utilizes Selenium and Playwright for enhanced DOM-based XSS detection.

---

## Steps to Install

1. Prerequisites
- Python 3.7 or later
- Browser drivers (e.g., ChromeDriver for Selenium)

2. Clone the Repository
```bash
  git clone https://github.com/AIwolfie/mayxss.git
  cd mayxss
```
3. Install Dependencies
Install the required Python libraries:
```bash
  pip install -r requirements.txt
```

4. Install Playwright Browsers
Set up Playwright for browser-based testing:
```bash
  playwright install
```

## Usage
**Basic Usage**
- To scan a single URL:
```bash
  python mayxss.py -u "http://example.com/FUZZ" -p payloads.txt
```

**To scan multiple URLs from a file:**
```bash
  python mayxss.py -ul urls.txt -p payloads.txt
```

**Optional Arguments**
1. `-o`: Save vulnerable links to a file (e.g., `-o results.txt`).
2. `-t`: Number of threads (default: 10, min: 1, max: 50).
3. `-H`: Add custom headers (e.g., `-H "User-Agent:CustomAgent"`).
4. `-P`: Set a proxy server (e.g., `-P http://127.0.0.1:8080`).
5. `-d`: Add delay between requests in seconds (default: 0).
6. `-v`: Enable verbose mode for real-time scanning logs.

**Example Commands**
- Scanning with 20 Threads and Saving Results:
```bash
  python mayxss.py -ul urls.txt -p payloads.txt -o results.txt -t 20
```

- Using Custom Headers and Proxy:
```bash
  python mayxss.py -u "http://example.com/FUZZ" -p payloads.txt -H "User-Agent:CustomAgent" -P "http://127.0.0.1:8080"
```

## Output
- The tool generates the following outputs:
1. Console Output: Displays live scan results.
2. Saved Results: Vulnerable URLs stored in a file (if `-o` is specified).
3. HTML Report: A detailed report (`xss_report.html`) with charts summarizing detected vulnerabilities.

## Contribution
- `Contributions` are welcome! If you'd like to improve this tool, feel free to fork the repository, make your changes, and submit a pull request. You can also submit issues for bugs or feature requests.


## Authors
- [@Aiwolfie](https://github.com/AIwolfie)

## Disclaimer
This tool is intended for educational and ethical use only. Please ensure you have permission from the owner before testing any website. Misuse of this tool may lead to legal consequences.

Use responsibly and stay ethical!
