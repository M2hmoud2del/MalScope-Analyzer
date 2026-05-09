import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

# Load the API key from the .env file secretly
load_dotenv()

class LLMAnalyzer:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            genai.configure(api_key=api_key)
            # Using the fast, free-tier reasoning model
            self.model = genai.GenerativeModel('gemini-3.1-flash-lite')
        else:
            self.model = None
            print("Warning: GEMINI_API_KEY not found in .env file. AI Analysis will be disabled.")

    def analyze(self, scan_data):
        """
        Takes the scan dictionary, formats it as JSON, and returns a plain-text AI report.
        """
        if not self.model:
            return "AI Analysis Unavailable: API key missing or invalid."

        # Convert the technical scan data into formatted JSON strings for the AI
        static_json = json.dumps(scan_data.get('static', {}), indent=2)
        dynamic_json = json.dumps(scan_data.get('dynamic', {}), indent=2)

        # The Prompt: Instructing the AI to use reasoning for the malware analysis
        prompt = f"""
        You are a Senior Malware Research Specialist. 
        Analyze the following automated scan data and think step-by-step to identify potential threats.

        Target File: {scan_data.get('file', 'Unknown')}
        Engine Verdict: {scan_data.get('verdict', 'Unknown')}
        Risk Score: {scan_data.get('score', 'Unknown')}/100

        --- STATIC ANALYSIS DATA (JSON) ---
        {static_json}

        --- DYNAMIC ANALYSIS DATA (JSON) ---
        {dynamic_json}

        Based on the data above, provide a report strictly in this format:
        1. Threat Summary: (2-3 sentences explaining the primary risk)
        2. Suspicious Indicators: (Bullet points referencing specific JSON findings)
        3. Recommended Response: (Steps for a security analyst to take)
        
        IMPORTANT: Provide the response in pure plain text. DO NOT use any Markdown formatting (no asterisks, no hashes, no bolding).
        """

        try:
            # Send the prompt to Gemini
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"An error occurred during AI analysis: {str(e)}"