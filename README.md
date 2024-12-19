# Domain API Scanner

## Description
The Domain API Scanner is a Python-based tool that scans JavaScript chunk URLs for API endpoints, keys, and sensitive data. It uses predefined regex patterns to identify and extract useful information from the content. Results are saved in a dark-mode HTML report for easy analysis.

## Features
- Extracts API keys, URLs, endpoints, IP addresses, JWTs, and more.
- Identifies sensitive files and error messages.
- Processes multiple JavaScript chunk URLs from a file.
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

2. Prepare a text file (e.g., `file.txt`) with the JavaScript chunk URLs, one URL per line.

3. Run the script with the file as an argument:
   ```bash
   python domain_api_scanner.py -f file.txt
   ```

4. View the results:
   - The script generates an HTML file named `scan_results.html` in the same directory.
   - Open it in your browser to view the results.

### Example File Format
Contents of `file.txt`:
```
https://example.com/static/js/chunk1.js
https://example.com/static/js/chunk2.js
https://example.com/static/js/chunk3.js
```

### Output
- **API Keys**: Extracted API keys from the scanned content.
- **Endpoints**: Identified API endpoints.
- **Sensitive Data**: Includes credentials, JWTs, and error messages.

## License
This project is licensed under the MIT License.

---
Feel free to contribute or submit issues on the [GitHub repository](https://github.com/your-username/repository-name).

