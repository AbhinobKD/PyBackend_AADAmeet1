from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"status": "backend running"}

@app.post("/check-url")
def check_url(data: URLRequest):
    parsed = urlparse(data.url)

    if parsed.scheme not in ("http", "https"):
        return {"status": "invalid"}

    return {
        "status": "ok",
        "domain": parsed.netloc
    }
