from flask import Flask, request, render_template
import requests

app = Flask(__name__)

def get_cve_details(cve_code):
    url = f"https://cve.circl.lu/api/cve/{cve_code}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if 'id' in data:
            cve_id = data.get('id', 'N/A')
            description = data.get('summary', 'No description available.')
            published_date = data.get('Published', 'No date available.')
            last_modified_date = data.get('Last_Modified', 'No date available.')

            # Extracting CVSS details
            cvss = data.get('cvss', {})
            cvss_base_score = cvss.get('base', 'N/A') if isinstance(cvss, dict) else cvss
            impact = cvss.get('impact', 'N/A') if isinstance(cvss, dict) else 'N/A'
            exploitability = cvss.get('exploitability', 'N/A') if isinstance(cvss, dict) else 'N/A'

            # Extracting CWE and creating a URL
            cwe = data.get('cwe', 'N/A')
            cwe_id = cwe.split('-')[1] if cwe != 'N/A' else 'N/A'
            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html" if cwe_id != 'N/A' else None

            # Extracting CAPEC information
            capec = data.get('capec', [])

            # Extracting access vector, complexity, and authentication
            access = data.get('access', {})
            access_vector = access.get('vector', 'N/A')
            access_complexity = access.get('complexity', 'N/A')
            authentication = access.get('authentication', 'N/A')

            # Extracting impact details (Confidentiality, Integrity, Availability)
            impact_details = data.get('impact', {})
            confidentiality = impact_details.get('confidentiality', 'N/A')
            integrity = impact_details.get('integrity', 'N/A')
            availability = impact_details.get('availability', 'N/A')

            # Extracting references
            references = data.get('references', [])

            # Extracting vulnerable configurations
            vulnerable_configs = data.get('vulnerable_configuration', [])
            formatted_configs = [{'id': config.get('id', 'N/A'), 'title': config.get('title', 'No title available')} for config in vulnerable_configs]

            # Extracting vulnerable software
            vulnerable_software = data.get('vulnerable_software', [])

            # Formatting CAPEC details
            formatted_capec = []
            for item in capec:
                formatted_capec.append({
                    'id': item.get('id', 'N/A'),
                    'name': item.get('name', 'N/A'),
                    'summary': item.get('summary', 'No summary available.'),
                    'prerequisites': item.get('prerequisites', 'No prerequisites available.'),
                    'solutions': item.get('solutions', 'No solutions available.')
                })

            return {
                'CVE ID': cve_id,
                'Description': description,
                'Published Date': published_date,
                'Last Modified Date': last_modified_date,
                'CVSS Base Score': cvss_base_score,
                'Impact': impact,
                'Exploitability': exploitability,
                'CWE': cwe,
                'CWE URL': cwe_url,
                'CAPEC': formatted_capec,
                'Access Vector': access_vector,
                'Access Complexity': access_complexity,
                'Authentication': authentication,
                'Confidentiality': confidentiality,
                'Integrity': integrity,
                'Availability': availability,
                'References': references,
                'Vulnerable Configurations': formatted_configs,
                'Vulnerable Software': vulnerable_software
            }
        else:
            return {'error': 'CVE not found or data is missing.'}

    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_code = request.form.get('cve_code')
        details = get_cve_details(cve_code)
        return render_template('index.html', details=details)
    return render_template('index.html', details={})

if __name__ == "__main__":
    app.run(debug=True)
