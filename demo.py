import json
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
if __name__=="__main__":
    client.post("/api/demo/reset")
    data=json.loads((Path(__file__).parent/"sample_data"/"brute_force.json").read_text())
    print(json.dumps(client.post("/api/events/batch",json=data).json(),indent=2))
    print(json.dumps(client.get("/api/alerts").json(),indent=2))
