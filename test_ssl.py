import urllib.request
import ssl
import json

url = "https://api.mistral.ai/v1/chat/completions"
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": "Bearer L2VFomnZInKESHY9uZxMrdfIt4xicGnK",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

payload = {
    "model": "mistral-large-latest",
    "messages": [
        {"role": "user", "content": "say test"}
    ]
}

print("Testing standard SSL request...")
try:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as response:
        print("Success standard:", response.read().decode("utf-8"))
except Exception as e:
    print("Failed standard:", e)

print("\nTesting with unverified context...")
try:
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
        print("Success unverified:", response.read().decode("utf-8"))
except Exception as e:
    print("Failed unverified:", e)
