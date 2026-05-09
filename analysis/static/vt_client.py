import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Load the VirusTotal API Key from the environment
API_KEY = os.environ.get("VT_API_KEY")

def get_vt_report(file_hash):
    """
    Queries the VirusTotal API (v3) to see if a file hash has been flagged.
    Returns a dictionary suitable for JSON output.
    """
    if not API_KEY:
        error_msg = "VT_API_KEY is missing from .env file"
        print(f"[-] {error_msg}")
        return {"status": "error", "message": error_msg}
        
    if not file_hash or file_hash == "Error calculating hash":
        return {"status": "error", "message": "Invalid Hash"}
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            permalink = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
            
            if not stats:
                print(f"[i] Hash not found on VT")
                return {"status": "error", "message": "Hash not found on VT"}
                
            stats["total"] = sum(stats.values())
            
            return {
                "status": "success",
                "detections": stats,
                "permalink": permalink
            }
            
        elif response.status_code == 404:
            print("[i] Hash not found on VT")
            return {"status": "error", "message": "Hash not found on VT"}
            
        elif response.status_code in (401, 403):
            error_msg = f"VT API Error {response.status_code}: Invalid or Unauthorized API Key"
            print(f"[-] {error_msg}")
            return {"status": "error", "message": error_msg}
            
        elif response.status_code == 429:
            error_msg = "VT API Error 429: Rate Limit Exceeded"
            print(f"[-] {error_msg}")
            return {"status": "error", "message": error_msg}
            
        else:
            error_msg = f"VT API Error: HTTP {response.status_code}"
            print(f"[-] {error_msg}")
            return {"status": "error", "message": error_msg}
            
    except requests.exceptions.RequestException as e:
        error_msg = "VT Connection Error (Check your internet)"
        print(f"[-] {error_msg}: {e}")
        return {"status": "error", "message": error_msg}
    except Exception as e:
        error_msg = "VT Processing Error"
        print(f"[-] {error_msg}: {e}")
        return {"status": "error", "message": error_msg}
