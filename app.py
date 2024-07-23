from flask import Flask, request, jsonify, render_template
from cve_api import get_cve_details
from chatbot import generate_response

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    user_input = request.form['user_input']
    cve_id = extract_cve_id(user_input)
    cve_details = get_cve_details(cve_id)
    response = generate_response(user_input, cve_details)
    return jsonify(response=response)

def extract_cve_id(user_input):
    # Simple extraction logic for demonstration purposes
    words = user_input.split()
    for word in words:
        if word.startswith("CVE-"):
            return word
    return None

if __name__ == '__main__':
    app.run(debug=True)