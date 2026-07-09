import os
import requests
from dotenv import load_dotenv

# Load environment variables securely from .env file
load_dotenv()

# Fetch the API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

def generate_threat_analysis(user_id, action, resource, location, time):
    """
    Smart REST API approach: Dynamically finds an active model and runs it.
    """
    if not GEMINI_API_KEY:
        return "❌ Error: GEMINI_API_KEY not found in environment variables."

    try:
        # STEP 1: Dynamically find an available model for your specific account
        list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={GEMINI_API_KEY}"
        list_response = requests.get(list_url)
        
        if list_response.status_code != 200:
            return f"Model listing failed. Details: {list_response.text}"
            
        models_data = list_response.json()
        valid_model = None
        
        # Find any active model that supports text generation (generateContent)
        for model in models_data.get('models', []):
            methods = model.get('supportedGenerationMethods', [])
            name = model.get('name', '')
            # We want a basic text-based gemini model
            if 'generateContent' in methods and 'gemini' in name and 'vision' not in name:
                valid_model = name # Automatically gets the 'models/gemini-x.x' format
                break
                
        if not valid_model:
            return "❌ Error: No text generation models available for this API key."

        # STEP 2: Make the actual request using the verified, active model
        url = f"https://generativelanguage.googleapis.com/v1beta/{valid_model}:generateContent?key={GEMINI_API_KEY}"
        
        prompt = f"""
        You are an expert cybersecurity analyst for an industrial enterprise. 
        Analyze the following anomalous access event and write a 2-3 sentence threat analysis report explaining WHY this might be dangerous. 
        Keep it professional and concise.
        
        Data:
        - User: {user_id}
        - Action: {action}
        - Resource Accessed: {resource}
        - Location: {location}
        - Time: {time}
        """
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, json=payload, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            return data['candidates'][0]['content']['parts'][0]['text'].strip()
        else:
            return f"AI Analysis failed on model {valid_model}. Details: {response.text}"
            
    except Exception as e:
        return f"AI Analysis error: {e}"

# --- TESTING ---
if __name__ == "__main__":
    print("Testing Secure AI Analyst (Auto-Detect Model)...")
    analysis = generate_threat_analysis("user_003", "view", "encryption_keys.dat", "New York", "01:32 AM")
    print("\n[AI Threat Report]:")
    print(analysis)