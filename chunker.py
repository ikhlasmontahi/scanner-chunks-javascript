import requests
import re

patterns = {
    'api_keys': r"[\'"](?:[A-Za-z0-9-]{32,})[\'"]|[A-Za-z0-9-]{32,40}|AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|[0-9a-zA-Z/+]{40}",
    'urls': r"https?://[^\s/$.?#].[^\s]*",
    'endpoints': r"/[a-zA-Z0-9.%+-]+(?:/[a-zA-Z0-9.%+-]+)*",
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
    'cloud_storage_keys': r"(?i)(?:aws[-]?s3|azure[-]?storage|google[-]?cloud)[\'\":\s]*[0-9a-zA-Z\-/]{32,}",
}

# Function to fetch and process URLs
def fetch_urls(domain, subdomains, paths):
    results = []
    for subdomain in subdomains:
        for path in paths:
            url = f"https://{subdomain}.{domain}{path}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    results.append((url, response.text))
            except requests.RequestException as e:
                print(f"Error accessing {url}: {e}")
    return results

# Function to extract data using patterns
def extract_data(html_content):
    extracted_data = {key: set(re.findall(pattern, html_content)) for key, pattern in patterns.items()}
    return extracted_data

# Function to generate a dark-mode HTML report
def generate_html_report(results):
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scan Results</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #121212;
                color: #ffffff;
            }
            .section {
                margin-bottom: 20px;
                padding: 10px;
                border: 1px solid #444;
                background-color: #1e1e1e;
                border-radius: 5px;
            }
            h1, h2, h3 {
                color: #ffa500;
            }
            a {
                color: #00bcd4;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <h1>Scan Results</h1>
    """
    for domain, data in results.items():
        html_content += f"<div class='section'><h2>Results for {domain}</h2>"
        for key, items in data.items():
            html_content += f"<h3>{key.capitalize().replace('_', ' ')}</h3><ul>"
            for item in items:
                html_content += f"<li>{item}</li>"
            html_content += "</ul>"
        html_content += "</div>"
    html_content += "</body></html>"
    return html_content

# Example Usage
def main():
    domain = "example.com"
    subdomains = ["api", "www", "dev"]
    paths = ["/v1", "/v2", "/health", "/login"]

    # Fetch URLs and extract data
    results = {}
    for subdomain in subdomains:
        fetched_data = fetch_urls(domain, [subdomain], paths)
        for url, content in fetched_data:
            if subdomain not in results:
                results[subdomain] = {key: set() for key in patterns.keys()}
            extracted = extract_data(content)
            for key, items in extracted.items():
                results[subdomain][key].update(items)

    # Generate HTML report
    report = generate_html_report(results)
    with open("scan_results.html", "w", encoding="utf-8") as f:
        f.write(report)
    print("Scan results saved to scan_results.html")

if __name__ == "__main__":
    main()
