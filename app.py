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
            last_modified_date = data.get('Last Modified', 'No date available.')
            
            cvss = data.get('cvss', 'No CVSS score available.')
            cvss_base_score = cvss.get('base', 'N/A') if isinstance(cvss, dict) else 'N/A'
            
            references = data.get('references', [])
            references_list = references if references else ["No references available."]
            
            vulnerable_software = data.get('vulnerable_software', [])
            vulnerable_software_list = vulnerable_software if vulnerable_software else ["No vulnerable software information available."]

            return {
                'CVE ID': cve_id,
                'Description': description,
                'Published Date': published_date,
                'Last Modified Date': last_modified_date,
                'CVSS Base Score': cvss_base_score,
                'References': references_list,
                'Vulnerable Software': vulnerable_software_list
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
