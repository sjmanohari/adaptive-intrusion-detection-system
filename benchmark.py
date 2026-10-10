import time
from datetime import datetime,timezone,timedelta
from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
if __name__=="__main__":
    for n in (100,500,1000):
        client.post("/api/demo/reset"); start=time.perf_counter()
        for i in range(n):
            client.post("/api/events",json={"timestamp":(datetime.now(timezone.utc)+timedelta(milliseconds=i)).isoformat(),"source_ip":f"192.0.2.{i%250+1}","event_type":"normal_traffic"})
        print(f"{n} events: {time.perf_counter()-start:.3f}s")
