from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import requests
import base64
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY")

class URLRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"status": "backend running"}

@app.post("/check-url")
def check_url(data: URLRequest):
    if not VT_API_KEY:
        return {"status": "error", "reason": "VT_API_KEY missing"}

    headers = {
        "x-apikey": VT_API_KEY
    }

    # Step 1: submit URL
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": data.url}
    )

    if submit.status_code != 200:
        return {"status": "unknown"}

    analysis_id = submit.json()["data"]["id"]

    # Step 2: wait briefly (VT needs time)
    time.sleep(1.5)

    # Step 3: get analysis result
    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    if result.status_code != 200:
        return {"status": "unknown"}

    stats = result.json()["data"]["attributes"]["stats"]

    if stats["malicious"] > 0:
        return {"status": "malicious"}
    elif stats["suspicious"] > 0:
        return {"status": "suspicious"}
    else:
        return {"status": "safe"}
