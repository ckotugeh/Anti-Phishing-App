from fastapi import FastAPI
from pydantic import BaseModel
from detector import check_url

app = FastAPI()

class URLRequest(BaseModel):
    url: str

@app.post("/check")
def check_url_endpoint(request: URLRequest):
    result = check_url(request.url)
    return {"url": request.url, "result": result}
