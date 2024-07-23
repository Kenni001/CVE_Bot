import requests

def get_cve_details(cve_id):
    if not cve_id:
        return "CVE ID not found in the query."
    
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        cve_data = response.json()
        return format_cve_response(cve_data)
    else:
        return "CVE details not found."

def format_cve_response(cve_data):
    cve_item = cve_data['result']['CVE_Items'][0]
    cve_id = cve_item['cve']['CVE_data_meta']['ID']
    description = cve_item['cve']['description']['description_data'][0]['value']
    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    
    response = f"CVE ID: {cve_id}\nDescription: {description}\nMore details: {link}"
    return response