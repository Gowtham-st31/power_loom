#!/usr/bin/env python3
"""List all available Gemini models."""

import requests
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

api_key = os.getenv('GEMINI_API_KEY')

if not api_key:
    print("ERROR: GEMINI_API_KEY not found in environment variables")
    exit(1)

print(f"Using API Key: {api_key[:20]}...")
print("\n" + "="*80)
print("FETCHING AVAILABLE GEMINI MODELS")
print("="*80 + "\n")

try:
    # Fetch all available models
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    response = requests.get(url)
    response.raise_for_status()
    
    data = response.json()
    
    if 'models' in data:
        models = data['models']
        print(f"Total Models Available: {len(models)}\n")
        
        for idx, model in enumerate(models, 1):
            model_name = model.get('name', 'Unknown')
            display_name = model.get('displayName', 'N/A')
            version = model.get('version', 'N/A')
            description = model.get('description', 'No description')
            
            print(f"{idx}. {display_name}")
            print(f"   Name: {model_name}")
            print(f"   Version: {version}")
            print(f"   Description: {description}")
            print()
    else:
        print("No models found in response")
        print(json.dumps(data, indent=2))
        
except requests.exceptions.RequestException as e:
    print(f"ERROR: {e}")
    if hasattr(e.response, 'text'):
        print(f"Response: {e.response.text}")
except json.JSONDecodeError as e:
    print(f"ERROR: Failed to parse JSON response: {e}")
except Exception as e:
    print(f"ERROR: {e}")
