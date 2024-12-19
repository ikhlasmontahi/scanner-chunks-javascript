# Chunks Scanner

## Description
The Chunk Scanner is a Python-based tool designed to scan JavaScript chunk files for sensitive data such as API keys, endpoints, JWTs, and more. The tool fetches these chunk URLs from a text file, analyzes their content using regex patterns, and generates a dark-themed HTML report.

## Features
- Extracts API keys, URLs, JWTs, IP addresses, credentials, and more.
- Processes multiple JavaScript chunk URLs from a file.
- Generates a user-friendly HTML report.
- Supports manual or automated collection of chunk URLs.

## Usage

### Prerequisites
- Python 3.x
- `requests` module

Install dependencies:
```bash
pip install requests
```

### Steps

1. Collect JavaScript chunk URLs:
   - **Option 1**: Use tools like `waybackurls` to fetch archived URLs for the target domain.
   - **Option 2**: Browse the target site thoroughly, capture requests in Burp Suite, and filter JavaScript chunk URLs.
   - Save these URLs in a text file (e.g., `urls-js.txt`).

2. Clone the repository:
   ```bash
   git clone https://github.com/your-username/chunk-scanner.git
   cd chunk-scanner
   ```

3. Run the script with your URLs file:
   ```bash
   python3 chunk_scanner.py -f urls-js.txt
   ```

4. View the results:
   - The script generates an HTML file named `scan_results.html` in the same directory.
   - Open this file in a browser to review the extracted data.

### Example File Format
Contents of `urls-js.txt`:
```
https://example.com/static/js/chunk1.js
https://example.com/static/js/chunk2.js
https://example.com/static/js/chunk3.js
```

### Output
The output includes:
- **API Keys**: Identified API keys.
- **Endpoints**: Extracted API endpoints.
- **JWTs**: Detected JSON Web Tokens.
- **Credentials**: Usernames and passwords.
- **Error Messages**: Useful for debugging and potential vulnerabilities.

## License
This project is licensed under the MIT License.

---
Feel free to contribute or submit issues on the [GitHub repository](https://github.com/your-username/chunk-scanner).

