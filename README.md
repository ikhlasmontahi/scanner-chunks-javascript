# Domain API Scanner

## Description
The Domain API Scanner is a Python-based tool that scans multiple domains and subdomains for API endpoints, keys, and sensitive data. It uses predefined regex patterns to identify and extract useful information from HTML content. Results are saved in a dark-mode HTML report for easy analysis.

## Features
- Extracts API keys, URLs, endpoints, IP addresses, JWTs, and more.
- Identifies sensitive files and error messages.
- Supports scanning across multiple subdomains and paths.
- Generates a visually appealing HTML report with results.

## Usage

### Prerequisites
- Python 3.x
- `requests` module

Install dependencies:
```bash
pip install requests
```

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/repository-name.git
   cd repository-name
   ```

2. Edit the `main()` function in the script to specify:
   - **Domain**: The target domain to scan.
   - **Subdomains**: List of subdomains to scan.
   - **Paths**: API paths to check.

3. Run the script:
   ```bash
   python domain_api_scanner.py
   ```

4. View the results:
   - The script generates an HTML file named `scan_results.html` in the same directory.
   - Open it in your browser to view the results.

### Example Configuration
In the `main()` function:
```python
    domain = "example.com"
    subdomains = ["api", "www", "dev"]
    paths = ["/v1", "/v2", "/health", "/login"]
```

### Output
- **API Keys**: Extracted API keys from the scanned content.
- **Endpoints**: Identified API endpoints.
- **Sensitive Data**: Includes credentials, JWTs, and error messages.

## License
This project is licensed under the MIT License.

---
Feel free to contribute or submit issues on the [GitHub repository](https://github.com/your-username/repository-name).

