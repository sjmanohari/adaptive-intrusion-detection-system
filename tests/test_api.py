from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
def setup_function(): client.post("/api/demo/reset")
def test_health(): assert client.get("/api/health").json()["status"]=="ok"
def test_brute_force_alert():
    events=[{"timestamp":f"2026-01-01T00:00:0{i}Z","source_ip":"192.0.2.10","event_type":"failed_login","username":"demo"} for i in range(5)]
    r=client.post("/api/events/batch",json={"events":events})
    assert r.status_code==200
    assert any(a["attack_category"]=="BRUTE_FORCE" for a in client.get("/api/alerts").json()["alerts"])
def test_invalid_ip():
    assert client.post("/api/events",json={"source_ip":"bad","event_type":"failed_login"}).status_code==422
def test_graph_endpoint(): assert client.get("/api/graph").status_code==200
