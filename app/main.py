from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from collections import defaultdict, deque, Counter
from datetime import datetime, timezone, timedelta
from threading import RLock
from uuid import uuid4
import ipaddress, os

app=FastAPI(title="Adaptive Intrusion Detection API", version="1.0.0",
 description="DSA-based IDS using sliding windows, hash tables, and graph threat correlation.")
LOCK=RLock()
CONFIG={"window_seconds":60,"failed_login_threshold":5,"request_threshold":100,
        "unique_ports_threshold":8,"suspicious_connection_threshold":4,"adaptive_enabled":True}
WINDOWS=defaultdict(deque)
TRACKER=defaultdict(list)
GRAPH=defaultdict(set)
NODES={}
EDGES={}
ALERTS=[]
EVENTS=deque(maxlen=10000)
STATS=Counter()
BASELINES=defaultdict(list)

class Event(BaseModel):
    event_id: str|None=None
    timestamp: datetime=Field(default_factory=lambda:datetime.now(timezone.utc))
    source_ip: str
    destination_ip: str|None=None
    source_port: int|None=Field(default=None,ge=0,le=65535)
    destination_port: int|None=Field(default=None,ge=0,le=65535)
    protocol: str="unknown"
    event_type: str
    username: str|None=None
    status: str|None=None
    metadata: dict={}
    @field_validator("source_ip","destination_ip")
    @classmethod
    def valid_ip(cls,v):
        if v is None:return v
        try:return str(ipaddress.ip_address(v))
        except ValueError as e: raise ValueError("must be a valid IPv4 or IPv6 address") from e
    @field_validator("timestamp")
    @classmethod
    def aware(cls,v):
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v

class Batch(BaseModel):
    events:list[Event]=Field(max_length=1000)

class ConfigPatch(BaseModel):
    window_seconds:int|None=Field(default=None,ge=1,le=3600)
    failed_login_threshold:int|None=Field(default=None,ge=1,le=10000)
    request_threshold:int|None=Field(default=None,ge=1,le=100000)
    unique_ports_threshold:int|None=Field(default=None,ge=2,le=65535)
    suspicious_connection_threshold:int|None=Field(default=None,ge=1,le=10000)
    adaptive_enabled:bool|None=None

def add_alert(ip,category,severity,score,evidence,entities,methods,action,event_ids):
    a={"alert_id":str(uuid4()),"timestamp":datetime.now(timezone.utc).isoformat(),
       "source_ip":ip,"attack_category":category,"severity":severity,
       "risk_score":max(0,min(100,int(score))),"evidence":evidence,
       "correlated_entities":entities,"detection_method":methods,
       "recommended_action":action,"event_ids":list(dict.fromkeys(event_ids))}
    ALERTS.append(a); STATS["alerts_generated"]+=1; STATS["severity:"+severity]+=1
    return a

def graph_edge(a,b,event_id,ts):
    GRAPH[a].add(b); GRAPH[b].add(a)
    NODES[a]={"id":a,"last_seen":ts.isoformat()}; NODES[b]={"id":b,"last_seen":ts.isoformat()}
    key=tuple(sorted((a,b)))
    edge=EDGES.setdefault(key,{"source":key[0],"target":key[1],"event_ids":[],"timestamps":[]})
    edge["event_ids"].append(event_id); edge["timestamps"].append(ts.isoformat())

def prune_graph(now):
    cutoff=now-timedelta(seconds=3600)
    for key,e in list(EDGES.items()):
        pairs=[(i,datetime.fromisoformat(t)) for i,t in zip(e["event_ids"],e["timestamps"])]
        pairs=[p for p in pairs if p[1]>=cutoff]
        if not pairs:
            EDGES.pop(key,None); a,b=key; GRAPH[a].discard(b); GRAPH[b].discard(a)
        else:e["event_ids"]=[p[0] for p in pairs]; e["timestamps"]=[p[1].isoformat() for p in pairs]
    for n in list(GRAPH):
        if not GRAPH[n]:GRAPH.pop(n,None); NODES.pop(n,None)
    while len(NODES)>5000:
        oldest=min(NODES,key=lambda n:NODES[n]["last_seen"])
        for neighbor in list(GRAPH.get(oldest,())):
            GRAPH[neighbor].discard(oldest); EDGES.pop(tuple(sorted((oldest,neighbor))),None)
        GRAPH.pop(oldest,None); NODES.pop(oldest,None)

def component(start):
    seen={start}; q=deque([start])
    while q:
        n=q.popleft()
        for nxt in GRAPH.get(n,()):
            if nxt not in seen:seen.add(nxt);q.append(nxt)
    return sorted(seen)

def process(ev):
    d=ev.model_dump(mode="json"); ts=ev.timestamp
    d["event_id"]=d.get("event_id") or str(uuid4()); d["timestamp"]=ts
    ip=d["source_ip"]; cutoff=ts-timedelta(seconds=CONFIG["window_seconds"])
    q=WINDOWS[ip]
    while q and q[0]["timestamp"]<cutoff:q.popleft()
    q.append(d); TRACKER[ip].append(d); EVENTS.append(d)
    # Retain tracker only for this IP's recent time window.
    TRACKER[ip]=[e for e in TRACKER[ip] if e["timestamp"]>=cutoff]
    recent=list(q); STATS["processed_events"]+=1; STATS["event_type:"+ev.event_type]+=1
    fails=[e for e in recent if e["event_type"]=="failed_login"]
    reqs=[e for e in recent if e["event_type"] in ("http_request","normal_traffic")]
    ports={e["destination_port"] for e in recent if e.get("destination_port") is not None}
    sus=[e for e in recent if e["event_type"]=="suspicious_connection"]
    BASELINES[ev.event_type].append(len(recent))
    if len(BASELINES[ev.event_type])>100:del BASELINES[ev.event_type][:-100]
    def threshold(kind,static):
        samples=BASELINES.get(kind,[])
        if not CONFIG["adaptive_enabled"] or len(samples)<10:return static,"static-rule fallback (insufficient baseline)"
        # Baseline can only increase, never decrease, the static floor; capped at 3x.
        med=sorted(samples[-20:])[len(samples[-20:])//2]
        return max(static,min(int(max(1,med)*2),static*3)),f"adaptive threshold from recent median baseline {med}"
    alerts=[]
    ft,fr=threshold("failed_login",CONFIG["failed_login_threshold"])
    rt,rr=threshold("http_request",CONFIG["request_threshold"])
    pt,pr=threshold("port_scan",CONFIG["unique_ports_threshold"])
    st,sr=threshold("suspicious_connection",CONFIG["suspicious_connection_threshold"])
    if len(fails)>=ft:alerts.append(add_alert(ip,"BRUTE_FORCE","HIGH",min(100,60+3*len(fails)),[f"{len(fails)} failed logins within {CONFIG['window_seconds']} seconds",fr],["ip:"+ip],["sliding_window","hash_table"],"Rate-limit authentication and review account logs.",[e["event_id"] for e in fails]))
    if len(reqs)>=rt:alerts.append(add_alert(ip,"EXCESSIVE_REQUESTS","HIGH",min(100,55+len(reqs)//2),[f"{len(reqs)} request events within the active window",rr],["ip:"+ip],["sliding_window","hash_table"],"Apply rate limits and investigate traffic volume.",[e["event_id"] for e in reqs]))
    if len(ports)>=pt:alerts.append(add_alert(ip,"PORT_SCAN","HIGH",min(100,60+2*len(ports)),[f"{len(ports)} unique destination ports contacted",pr],["ip:"+ip]+["port:"+str(p) for p in sorted(ports)],["sliding_window","hash_table"],"Review connection logs and apply filtering if warranted.",[e["event_id"] for e in recent if e.get("destination_port") is not None]))
    if len(sus)>=st:alerts.append(add_alert(ip,"SUSPICIOUS_CONNECTIONS","MEDIUM",min(100,45+5*len(sus)),[f"{len(sus)} suspicious connections within active window",sr],["ip:"+ip],["sliding_window"],"Investigate destinations and associated activity.",[e["event_id"] for e in sus]))
    # Only suspicious events add graph edges; normal traffic does not create clusters.
    if ev.event_type in ("failed_login","port_scan","suspicious_connection") or alerts:
        source="ip:"+ip; graph_edge(source,"event:"+d["event_id"],d["event_id"],ts)
        if d.get("destination_ip"):graph_edge(source,"ip:"+d["destination_ip"],d["event_id"],ts)
        if d.get("username"):graph_edge(source,"user:"+d["username"],d["event_id"],ts)
        if d.get("destination_port") is not None:graph_edge(source,"port:"+str(d["destination_port"]),d["event_id"],ts)
        prune_graph(ts); comp=component(source); eventids=[n[6:] for n in comp if n.startswith("event:")]
        if len(set(eventids))>=3:
            alerts.append(add_alert(ip,"CORRELATED_THREAT_CLUSTER","CRITICAL",min(100,70+3*len(set(eventids))),[f"Graph BFS connected {len(set(eventids))} suspicious events through shared entities."],comp[:100],["graph_bfs","threat_correlation"],"Investigate as a related incident; validate evidence before blocking.",eventids))
    return {"event_id":d["event_id"],"alerts":alerts,"window_event_count":len(recent)}

@app.get("/")
def root():return {"message":"Adaptive IDS backend is running","docs":"/docs","health":"/api/health"}
@app.get("/api/health")
def health():return {"service":"Adaptive DSA-Based Intrusion Detection System","status":"ok","version":"1.0.0"}
@app.post("/api/events")
def submit_event(event:Event):
    with LOCK:return {"status":"processed",**process(event)}
@app.post("/api/events/batch")
def submit_batch(batch:Batch):
    with LOCK:return {"status":"processed","submitted":len(batch.events),"results":[process(e) for e in batch.events]}
@app.get("/api/alerts")
def get_alerts(offset:int=Query(0,ge=0),limit:int=Query(50,ge=1,le=200),severity:str|None=None,category:str|None=None):
    with LOCK:
        rows=list(reversed(ALERTS))
        if severity:rows=[a for a in rows if a["severity"]==severity.upper()]
        if category:rows=[a for a in rows if a["attack_category"]==category.upper()]
        return {"total":len(rows),"offset":offset,"limit":limit,"alerts":rows[offset:offset+limit]}
@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id:str):
    with LOCK:
        for a in ALERTS:
            if a["alert_id"]==alert_id:return a
    raise HTTPException(404,"Alert not found")
@app.get("/api/stats")
def stats():
    with LOCK:return {"processed_events":STATS["processed_events"],"alerts_generated":STATS["alerts_generated"],
      "severity_distribution":{k.split(":",1)[1]:v for k,v in STATS.items() if k.startswith("severity:")},
      "event_type_distribution":{k.split(":",1)[1]:v for k,v in STATS.items() if k.startswith("event_type:")},
      "retained_event_count":len(EVENTS),"graph":{"nodes":len(NODES),"edges":len(EDGES)}}
@app.get("/api/graph")
def graph():
    with LOCK:return {"nodes":list(NODES.values()),"edges":list(EDGES.values()),"clusters":[c for c in _clusters() if len(c)>1],"node_count":len(NODES),"edge_count":len(EDGES)}
def _clusters():
    seen=set();out=[]
    for n in list(GRAPH):
        if n not in seen:
            c=component(n);seen.update(c);out.append(c)
    return sorted(out,key=lambda c:(-len(c),c[0]))
@app.get("/api/ip/{ip_address}")
def ip_info(ip_address:str):
    try:ip=str(ipaddress.ip_address(ip_address))
    except ValueError:raise HTTPException(422,"Invalid IPv4 or IPv6 address")
    with LOCK:
        events=TRACKER.get(ip,[])
        return {"ip":ip,"recent_event_count":len(events),"counts_by_type":dict(Counter(e["event_type"] for e in events)),"latest_events":events[-20:]}
@app.get("/api/config")
def get_config():return dict(CONFIG)
@app.patch("/api/config")
def patch_config(patch:ConfigPatch):
    changes=patch.model_dump(exclude_none=True)
    with LOCK:
        CONFIG.update(changes)
        return {"status":"updated","config":dict(CONFIG)}
@app.post("/api/demo/reset")
def reset_demo():
    with LOCK:
        WINDOWS.clear();TRACKER.clear();GRAPH.clear();NODES.clear();EDGES.clear();ALERTS.clear();EVENTS.clear();STATS.clear();BASELINES.clear()
    return {"status":"reset","message":"In-memory demo state cleared"}
