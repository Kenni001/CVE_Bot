import openai

openai.api_key = 'your-openai-api-key'

def generate_response(user_input, cve_details):
    prompt = f"User asked: {user_input}\n\nCVE Details: {cve_details}\n\nResponse:"
    
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=150
    )
    
    return response.choices[0].text.strip()