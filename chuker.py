import requests
import re
import argparse
from urllib.parse import urlparse
from pathlib import Path
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Define regex patterns
patterns = {
    'api_keys': r"[\'\"]([A-Za-z0-9-]{32,})[\'\"]|[A-Za-z0-9-]{32,40}|AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|[0-9a-zA-Z/+]{40}",
    'urls': r"https?://[^\s/$.?#].[^\s]*",
    'endpoints': r"/[a-zA-Z0-9._%+-]+(?:/[a-zA-Z0-9._%+-]+)*",
    'ipv4': r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    'ipv6': r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    'basic_auth': r"Basic\s[0-9a-zA-Z+/=]{20,}",
    'jwt': r"eyJ[0-9a-zA-Z-]+\.[0-9a-zA-Z-]+\.[0-9a-zA-Z-_]+",
    'credentials': r"\"username\":\s*\"[^\s]+\"|\"password\":\s*\"[^\s]+\"",
    'secret_keys': r"(?i)(?:api[-]?key|access[-]?key|client[-]?secret|auth[-]?token|bearer[-]?token|x-api-key|x-access-token)[\'\":\s]*[0-9a-zA-Z\-/]{32,}",
    'emails': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    'phone_numbers': r"\+?[1-9]\d{1,14}$",
    'aws_keys': r"AKIA[0-9A-Z]{16}|[A-Z0-9]{20}|[0-9a-zA-Z/+]{40}",
    'sensitive_files': r"\b(?:config|secret|key|credentials|auth)\b",
    'error_messages': r"(error|failed|unauthorized|invalid|forbidden|exception|warning|fatal)\b",
    'database_connection_strings': r"(?i)(?:mysql|postgresql|mssql|oracle|sqlite|mongodb|redis)[\w\W]?//[^s]\b",
    'cloud_storage_keys': r"(?i)(?:aws[-]?s3|azure[-]?storage|google[-]?cloud)[\'\":\s]*[0-9a-zA-Z\-/]{32,}"
}

def fetch_and_scan(url):
    """Fetch the content of a URL and scan for sensitive information."""
    results = {}
    try:
        response = requests.get(url, verify=False, timeout=10)
        content = response.text
        for pattern_name, pattern_regex in patterns.items():
            matches = re.findall(pattern_regex, content)
            if matches:
                results[pattern_name] = matches
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
    return results

def generate_html(results):
    """Generate an HTML file with the scan results organized by domain and pattern type."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scan Results</title>
        <style>
            body { font-family: Arial, sans-serif; }
            .section { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; }
            .section h2 { margin-top: 0; }
            .pattern-section { margin-bottom: 15px; }
            .endpoint-link { display: block; }
        </style>
        <script>
            function updateEndpoints(domain) {
                let links = document.querySelectorAll(".endpoint-link");
                links.forEach(link => {
                    let path = link.getAttribute("data-path");
                    link.href = domain + path;
                    link.textContent = domain + path;
                });
            }
        </script>
    </head>
    <body>
        <h1>Scan Results</h1>
        <label for="domainInput">Set Domain for Endpoints:</label>
        <input type="text" id="domainInput" placeholder="https://example.com" oninput="updateEndpoints(this.value)">
    """

    for url, patterns_found in results.items():
        domain = urlparse(url).netloc
        html_content += f"""
        <div class="section">
            <h2>Results from: {domain}</h2>
            <p>Source: <a href="{url}" target="_blank">{url}</a></p>
        """
        for pattern, items in patterns_found.items():
            html_content += f"""
            <div class="pattern-section">
                <h3>{pattern.capitalize()}</h3>
                <ul>
            """
            for item in items:
                if pattern == 'endpoints':
                    html_content += f'<li><a href="#" class="endpoint-link" data-path="{item}">{item}</a></li>'
                else:
                    html_content += f"<li>{item}</li>"
            html_content += "</ul></div>"

        html_content += "</div>"

    html_content += """
    </body>
    </html>
    """

    with open("scan_results.html", "w") as file:
        file.write(html_content)
    print("HTML report generated: scan_results.html")

def process_js_chunks(file_path):
    """Process each JavaScript chunk URL from the provided file."""
    with open(file_path, 'r') as file:
        urls = file.read().splitlines()

    final_results = {}
    for url in urls:
        print(f"Processing {url}...")
        matches = fetch_and_scan(url)
        if matches:
            final_results[url] = matches

    generate_html(final_results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan JavaScript chunks for sensitive information and generate HTML report.")
    parser.add_argument("-f", "--file", required=True, help="File containing list of JavaScript chunk URLs")
    args = parser.parse_args()
    process_js_chunks(args.file)
