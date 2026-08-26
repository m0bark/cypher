"""A tiny localhost web UI for Cypher, built on the standard library only.

Serves one page: an OSINT console with a category sidebar, a search bar, a
compact options strip, and results (entity graph + Claude correlation + findings).
The Anthropic key is built in — it loads from .env/environment automatically, and
the UI can save a pasted key back to .env. Results can also be written into an
Obsidian vault.

Binds to 127.0.0.1 only. The key is used for the run and only persisted to .env
if you explicitly ask (never logged, never committed — .env is gitignored).
"""

from __future__ import annotations

import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..ai.orchestrator import Orchestrator
from ..core.context import Context
from ..core.registry import discover
from ..core.scope import assess, looks_personal
from ..core.settings import Settings
from ..core.target import TargetType, parse_target
from ..report.obsidian import write_note
from ..report.renderer import write_report

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
ENV_PATH = ".env"


def _save_env_key(key: str) -> bool:
    """Create/update ANTHROPIC_API_KEY in .env without disturbing other lines."""
    line = f"ANTHROPIC_API_KEY={key}\n"
    try:
        existing = []
        if os.path.exists(ENV_PATH):
            with open(ENV_PATH, encoding="utf-8") as fh:
                existing = fh.readlines()
        replaced = False
        for i, ln in enumerate(existing):
            if ln.strip().startswith("ANTHROPIC_API_KEY="):
                existing[i] = line
                replaced = True
                break
        if not replaced:
            existing.append(line)
        with open(ENV_PATH, "w", encoding="utf-8") as fh:
            fh.writelines(existing)
        os.environ["ANTHROPIC_API_KEY"] = key
        return True
    except Exception:
        return False


def _build_graph(inv) -> dict:
    """Build a node/link graph: target -> module -> discovered entities."""
    nodes: dict[str, dict] = {}
    links: list[dict] = []

    def add(node_id: str, label: str, group: str) -> None:
        nodes.setdefault(node_id, {"id": node_id, "label": label, "group": group})

    root = inv.target.value
    add(root, root, inv.target.type.value)
    for res in inv.results:
        if res.skipped or not res.ok or not res.findings:
            continue
        mid = f"mod:{res.module}"
        add(mid, res.module, "module")
        links.append({"source": root, "target": mid})
        for nt in res.new_targets:
            if nt.value == root:
                continue
            add(nt.value, nt.value, nt.type.value)
            links.append({"source": mid, "target": nt.value})
    return {"nodes": list(nodes.values()), "links": links}


def run_investigation(payload: dict) -> dict:
    raw = (payload.get("target") or "").strip()
    if not raw:
        return {"ok": False, "error": "No target provided."}

    target = parse_target(raw)
    if target.type is TargetType.UNKNOWN:
        return {"ok": False, "error": f"Could not classify target '{raw}'."}

    decision = assess(target)
    if not decision.allowed:
        return {"ok": False, "error": f"Refused: {decision.reason}"}
    if not payload.get("authorized"):
        return {"ok": False, "error": "Tick the authorization box to continue."}
    if decision.requires_confirmation and looks_personal(target) and not payload.get("personal_ok"):
        return {"ok": False, "error": decision.reason, "needs_personal_ok": True}

    settings = Settings.load()
    key = (payload.get("api_key") or "").strip()
    saved_key = False
    if key:
        settings.anthropic_api_key = key
        if payload.get("save_key"):
            saved_key = _save_env_key(key)
    if payload.get("passive"):
        settings.passive_only = True

    use_ai = bool(settings.anthropic_api_key) and not payload.get("no_ai")
    depth = int(payload.get("depth") or 1)
    only = payload.get("modules") or None

    ctx = Context.create(settings)
    registry = discover()
    orch = Orchestrator(ctx, registry, use_ai=use_ai)
    obsidian_path = None
    try:
        inv = orch.investigate(target, only=only, depth=depth)
        orch.synthesize(inv)
        paths = write_report(inv, settings.output_dir)
        if payload.get("obsidian"):
            vault = (payload.get("vault") or "").strip() or settings.obsidian_vault
            if vault:
                obsidian_path = write_note(inv, vault)
    finally:
        ctx.close()

    return {
        "ok": True,
        "target": target.value,
        "target_type": target.type.value,
        "ai_used": inv.ai_used,
        "plan": inv.plan,
        "reasoning": inv.plan_reasoning,
        "summary": inv.summary,
        "graph": _build_graph(inv),
        "report_path": paths.get("markdown"),
        "obsidian_path": obsidian_path,
        "saved_key": saved_key,
        "results": [
            {
                "module": r.module,
                "ok": r.ok,
                "skipped": r.skipped,
                "error": r.error,
                "findings": [
                    {
                        "title": f.title,
                        "detail": f.detail,
                        "severity": f.severity.value,
                        "data": {k: f.data[k] for k in ("image", "bio", "url", "platform")
                                 if k in f.data},
                    }
                    for f in r.findings
                ],
            }
            for r in inv.results
        ],
    }


def _config() -> dict:
    s = Settings.load()
    return {"has_key": bool(s.anthropic_api_key), "default_vault": s.obsidian_vault or ""}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/config":
            self._json(200, _config())
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path != "/scan":
            self._send(404, b"not found", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception as exc:
            self._json(400, {"ok": False, "error": f"bad request: {exc}"})
            return
        try:
            result = run_investigation(payload)
        except Exception as exc:
            result = {"ok": False, "error": f"scan failed: {exc}"}
        self._json(200, result)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"Cypher UI running at {url}  (Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Cypher UI.")
    finally:
        server.server_close()


PAGE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cypher</title>
<style>
  :root{
    --bg:#080b11;--side:#0b0f16;--card:#111823;--card2:#0d141d;--line:#1c2836;
    --text:#dbe4ee;--muted:#6f8195;--faint:#455060;
    --accent:#39d0d8;--accent2:#7b8cff;
    --hi:#ff5d5d;--med:#ffb454;--low:#8ad4ff;--ok:#57d9a3;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--text);
    font:14px/1.55 ui-monospace,"Cascadia Code",Consolas,monospace}
  ::-webkit-scrollbar{width:10px;height:10px}
  ::-webkit-scrollbar-thumb{background:#1c2836;border-radius:6px}
  .app{display:grid;grid-template-columns:236px 1fr;height:100vh}

  /* ---- sidebar ---- */
  .side{background:var(--side);border-right:1px solid var(--line);display:flex;
    flex-direction:column;overflow:hidden}
  .brand{padding:20px 20px 14px;font-size:20px;letter-spacing:3px;font-weight:700}
  .brand i{color:var(--accent);font-style:normal}
  .brand small{display:block;font-size:10px;letter-spacing:2px;color:var(--muted);
    font-weight:400;margin-top:2px}
  .nav{padding:6px 10px;overflow-y:auto;flex:1}
  .nav-item{display:flex;justify-content:space-between;align-items:center;
    padding:9px 12px;border-radius:8px;color:var(--muted);cursor:pointer;
    font-size:13px;letter-spacing:.3px;user-select:none;transition:.12s}
  .nav-item:hover{background:#0f1620;color:var(--text)}
  .nav-item.active{background:#0f1a24;color:var(--text);
    box-shadow:inset 2px 0 0 var(--accent)}
  .nav-item b{font-weight:600;font-size:11px;color:var(--faint);
    background:#0c1219;border:1px solid var(--line);border-radius:20px;padding:1px 8px}
  .nav-item.active b{color:var(--accent);border-color:#22424a}
  .side-foot{padding:14px 20px;border-top:1px solid var(--line);
    font-size:10px;color:var(--faint);letter-spacing:.5px}

  /* ---- main ---- */
  .main{overflow-y:auto;display:flex;flex-direction:column}
  .topbar{position:sticky;top:0;z-index:5;background:linear-gradient(180deg,var(--bg),rgba(8,11,17,.9));
    backdrop-filter:blur(6px);border-bottom:1px solid var(--line);
    padding:16px 24px 12px;display:flex;gap:12px;align-items:center}
  .search{flex:1;background:var(--card2);border:1px solid var(--line);color:var(--text);
    border-radius:10px;padding:14px 16px;font:inherit;font-size:15px}
  .search:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(57,208,216,.12)}
  .run{background:var(--accent);color:#04252a;border:0;border-radius:10px;
    padding:0 26px;height:48px;font:inherit;font-weight:700;letter-spacing:2px;cursor:pointer}
  .run:hover{filter:brightness(1.08)} .run:disabled{opacity:.5;cursor:not-allowed}

  .opts{display:flex;flex-wrap:wrap;gap:14px;align-items:center;
    padding:12px 24px;border-bottom:1px solid var(--line);color:var(--muted);font-size:12px}
  .opts .keyf{background:var(--card2);border:1px solid var(--line);color:var(--text);
    border-radius:8px;padding:8px 10px;font:inherit;font-size:12px;width:230px}
  .opts .vault{background:var(--card2);border:1px solid var(--line);color:var(--text);
    border-radius:8px;padding:8px 10px;font:inherit;font-size:12px;width:190px}
  .opts input:focus{outline:none;border-color:var(--accent)}
  .chk{display:flex;align-items:center;gap:6px;color:var(--muted);white-space:nowrap}
  .chk input{accent-color:var(--accent)}
  .depth{width:42px;background:var(--card2);border:1px solid var(--line);color:var(--text);
    border-radius:6px;padding:4px 6px;font:inherit;text-align:center}
  .auth{color:var(--text)}

  .status{padding:12px 24px;color:var(--muted);min-height:20px;font-size:13px}
  .spin{display:inline-block;width:13px;height:13px;border:2px solid var(--line);
    border-top-color:var(--accent);border-radius:50%;animation:s .8s linear infinite;
    vertical-align:-2px;margin-right:8px}
  @keyframes s{to{transform:rotate(360deg)}}

  .out{padding:4px 24px 40px;display:flex;flex-direction:column;gap:16px}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .panel>h2{margin:0;padding:12px 16px;font-size:12px;letter-spacing:1.5px;text-transform:uppercase;
    color:var(--muted);border-bottom:1px solid var(--line);background:var(--card2);
    display:flex;justify-content:space-between;align-items:center}
  .panel>h2 .pill{font-size:10px;color:var(--accent);border:1px solid #22424a;border-radius:20px;padding:1px 10px}
  .panel .body{padding:16px}
  canvas#graph{width:100%;height:440px;display:block;background:var(--card2)}
  .summary{white-space:pre-wrap;font-size:13.5px;color:#c9d5e2}
  .mod{border:1px solid var(--line);border-radius:9px;margin-top:10px;overflow:hidden}
  .mod:first-child{margin-top:0}
  .mod h3{margin:0;padding:9px 13px;background:var(--card2);font-size:13px;
    display:flex;justify-content:space-between;align-items:center;cursor:default}
  .tag{font-size:10px;padding:2px 9px;border-radius:20px;letter-spacing:.5px}
  .t-ok{background:rgba(87,217,163,.14);color:var(--ok)}
  .t-skip{background:#0c1219;color:var(--faint)}
  .t-err{background:rgba(255,93,93,.14);color:var(--hi)}
  .f{padding:8px 13px;border-top:1px solid var(--line);font-size:12.5px;color:#bac7d4}
  .f b{color:var(--text)}
  .sev{font-size:9px;text-transform:uppercase;padding:1px 6px;border-radius:4px;margin-right:8px;letter-spacing:.5px}
  .s-high{background:var(--hi);color:#2a0000}.s-medium{background:var(--med);color:#2a1a00}
  .s-low{background:var(--low);color:#00202a}.s-info{background:var(--line);color:var(--muted)}
  /* profile confirm cards */
  .pgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
  .pcard{display:flex;gap:12px;background:var(--card2);border:1px solid var(--line);
    border-radius:10px;padding:12px;transition:.15s}
  .pcard.is-mine{border-color:#2a6b52;box-shadow:inset 0 0 0 1px #2a6b52}
  .pcard.not-mine{opacity:.4}
  .pcard img{width:56px;height:56px;border-radius:8px;object-fit:cover;background:#0a0e14;flex:none}
  .pmeta{flex:1;min-width:0}
  .plat{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--accent)}
  .pmeta b{display:block;font-size:13px;margin:1px 0}
  .pmeta p{margin:2px 0;font-size:11.5px;color:var(--muted);overflow:hidden;
    display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
  .pmeta a{font-size:11px;word-break:break-all}
  .pconfirm{display:flex;flex-direction:column;gap:6px;justify-content:center}
  .pconfirm button{background:#0c1219;border:1px solid var(--line);color:var(--muted);
    border-radius:6px;padding:4px 8px;font:inherit;font-size:11px;cursor:pointer}
  .pconfirm .mine:hover{border-color:#2a6b52;color:var(--ok)}
  .pconfirm .no:hover{border-color:#6b2a2a;color:var(--hi)}
  .gate{padding:0 24px 28px;font-size:11px;color:var(--faint);max-width:760px}
  .empty{padding:60px 24px;text-align:center;color:var(--faint);font-size:13px}
  a{color:var(--accent);text-decoration:none}

  @media(max-width:760px){
    .app{grid-template-columns:1fr}
    .side{display:none}
  }
</style></head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand">CY<i>PH</i>ER<small>OSINT CONSOLE</small></div>
    <div class="nav" id="nav"></div>
    <div class="side-foot">authorized &amp; defensive use only</div>
  </aside>
  <main class="main">
    <div class="topbar">
      <input id="target" class="search" placeholder="domain · IP · email · URL · username" autofocus>
      <button id="run" class="run">RUN</button>
    </div>
    <div class="opts">
      <label class="chk"><input type="checkbox" id="passive"> passive</label>
      <label class="chk">depth <input id="depth" class="depth" value="1"></label>
      <label class="chk"><input type="checkbox" id="obsidian"> obsidian</label>
      <input id="vault" class="vault" placeholder="Obsidian vault path (optional)">
      <label class="chk auth"><input type="checkbox" id="authorized"> authorized</label>
    </div>
    <div id="status" class="status"></div>
    <div id="out" class="out"><div class="empty">Enter a target and press RUN. Pick a category on the left to scope the modules.</div></div>
    <div class="gate">Cypher gathers only open-source data. Use it on assets you own or are permitted to assess, or for your own defensive checks — not to profile private individuals.</div>
  </main>
</div>
<script>
const $=id=>document.getElementById(id);
const CATS={
  "All modules":null,
  "Domain":["dns_records","rdap_whois","crtsh_subdomains","wayback","http_fingerprint","whois","subfinder","amass","assetfinder","findomain","sublist3r","dnsrecon","dnsenum","fierce","dnstwist","gau","waybackurls","urlscan"],
  "Email":["email_recon","breach_check","holehe","h8mail","mosint","socialscan"],
  "Username":["username_sites","github_recon","sherlock","maigret","socialscan","telegram","instagram"],
  "Instagram":["instagram"],
  "Telegram":["telegram"],
  "Phone":["phone_info"],
  "IP":["ip_info","rdap_whois","bgpview","shodan_host","nmap","naabu","rustscan"],
  "Web":["http_fingerprint","whatweb","wafw00f","httpx","katana","nuclei","nikto","gobuster","wpscan","sslscan"],
  "Ports":["nmap","naabu","rustscan"],
  "Breach":["breach_check","h8mail","holehe"]
};
let activeCat="All modules";
function buildNav(){
  const nav=$("nav");nav.innerHTML="";
  for(const name in CATS){
    const d=document.createElement("div");
    d.className="nav-item"+(name===activeCat?" active":"");
    const count=CATS[name]?CATS[name].length:43;
    d.innerHTML='<span>'+name+'</span><b>'+count+'</b>';
    d.onclick=()=>{activeCat=name;buildNav();};
    nav.appendChild(d);
  }
}
buildNav();
fetch("/config").then(r=>r.json()).then(c=>{
  if(!c.has_key)$("status").textContent="Note: no Claude key saved — using deterministic mode. Add ANTHROPIC_API_KEY to .env for AI correlation.";
  if(c.default_vault)$("vault").value=c.default_vault;
}).catch(()=>{});
$("run").onclick=async()=>{
  const body={target:$("target").value,
    passive:$("passive").checked,authorized:$("authorized").checked,personal_ok:true,
    obsidian:$("obsidian").checked,vault:$("vault").value,depth:parseInt($("depth").value)||1,
    modules:CATS[activeCat]};
  if(!body.target){$("status").textContent="Enter a target.";return;}
  if(!body.authorized){$("status").textContent="Tick 'authorized' to continue.";return;}
  $("run").disabled=true;$("out").innerHTML="";
  $("status").innerHTML='<span class="spin"></span>Running '+activeCat.toLowerCase()+' modules and connecting the dots…';
  try{
    const r=await fetch("/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){$("status").textContent="✗ "+d.error;$("run").disabled=false;return;}
    let msg="✓ "+d.results.length+" modules · "+(d.ai_used?"Claude analysis":"deterministic")+" · report saved";
    if(d.obsidian_path)msg+=" · Obsidian ✓";
    if(d.saved_key)msg+=" · key saved";
    $("status").textContent=msg;
    render(d);
  }catch(e){$("status").textContent="✗ "+e;$("out").innerHTML="";}
  $("run").disabled=false;
};
function esc(s){return (s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function profiles(d){
  const out=[];
  for(const m of d.results){for(const f of (m.findings||[])){
    const dt=f.data||{};
    if(dt.platform&&(dt.image||dt.bio)){
      out.push({platform:dt.platform,name:f.detail,bio:dt.bio||"",image:dt.image||"",url:dt.url||""});
    }
  }}
  return out;
}
function render(d){
  let h="";
  const profs=profiles(d);
  if(profs.length){
    h+='<div class="panel"><h2>Is this you?<span class="pill">'+profs.length+' profiles — confirm</span></h2><div class="body"><div class="pgrid">';
    for(const p of profs){
      h+='<div class="pcard">'
        +(p.image?'<img src="'+esc(p.image)+'" referrerpolicy="no-referrer" onerror="this.remove()">':'')
        +'<div class="pmeta"><span class="plat">'+esc(p.platform)+'</span><b>'+esc(p.name)+'</b>'
        +(p.bio?'<p>'+esc(p.bio)+'</p>':'')
        +(p.url?'<a href="'+esc(p.url)+'" target="_blank" rel="noreferrer">'+esc(p.url)+'</a>':'')
        +'</div><div class="pconfirm"><button class="mine">✓ mine</button><button class="no">✗ not</button></div></div>';
    }
    h+='</div><p style="font-size:11px;color:var(--faint);margin-top:10px">Compare the picture and bio to decide which accounts are actually yours.</p></div></div>';
  }
  if(d.graph&&d.graph.nodes.length){
    h+='<div class="panel"><h2>Entity network<span class="pill">'+d.graph.nodes.length+' nodes / '+d.graph.links.length+' links</span></h2>';
    h+='<canvas id="graph" width="900" height="440"></canvas></div>';
  }
  h+='<div class="panel"><h2>Intelligence summary<span class="pill">'+(d.ai_used?"Claude":"deterministic")+'</span></h2><div class="body summary">'+esc(d.summary)+'</div></div>';
  h+='<div class="panel"><h2>Module results<span class="pill">'+esc((d.plan||[]).join(" · "))+'</span></h2><div class="body">';
  for(const m of d.results){
    const cls=m.skipped?"t-skip":(m.ok?"t-ok":"t-err"),tag=m.skipped?"skip":(m.ok?"ok":"err");
    h+='<div class="mod"><h3><span>'+esc(m.module)+'</span><span class="tag '+cls+'">'+tag+'</span></h3>';
    if(m.error)h+='<div class="f">'+esc(m.error)+'</div>';
    for(const f of m.findings)h+='<div class="f"><span class="sev s-'+f.severity+'">'+f.severity+'</span><b>'+esc(f.title)+'</b> — '+esc(f.detail)+'</div>';
    h+='</div>';
  }
  h+='</div></div>';
  $("out").innerHTML=h;
  if(d.graph&&d.graph.nodes.length)drawGraph(d.graph);
}
let _raf=null;
function drawGraph(g){
  const cv=$("graph");if(!cv)return;
  const ctx=cv.getContext("2d"),W=cv.width,H=cv.height;
  const col={domain:"#8ad4ff",ip:"#57d9a3",email:"#ffb454",url:"#39d0d8",username:"#b79bff",module:"#6f8195"};
  const rootId=g.nodes[0].id;
  const nodes=g.nodes.map(n=>({...n,x:W/2+(Math.random()-.5)*240,y:H/2+(Math.random()-.5)*240,vx:0,vy:0}));
  const idx={};nodes.forEach((n,i)=>idx[n.id]=i);
  const links=g.links.filter(l=>l.source in idx&&l.target in idx);
  if(_raf)cancelAnimationFrame(_raf);
  function step(){
    for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i],b=nodes[j];let dx=a.x-b.x,dy=a.y-b.y,dd=Math.hypot(dx,dy)||1,f=1500/(dd*dd);
      dx/=dd;dy/=dd;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const l of links){const a=nodes[idx[l.source]],b=nodes[idx[l.target]];
      let dx=b.x-a.x,dy=b.y-a.y,dd=Math.hypot(dx,dy)||1,f=(dd-95)*.02;
      dx/=dd;dy/=dd;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const n of nodes){n.vx+=(W/2-n.x)*.002;n.vy+=(H/2-n.y)*.002;n.vx*=.85;n.vy*=.85;n.x+=n.vx;n.y+=n.vy;}
    ctx.clearRect(0,0,W,H);ctx.strokeStyle="#1c2836";ctx.lineWidth=1;
    for(const l of links){const a=nodes[idx[l.source]],b=nodes[idx[l.target]];
      ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
    ctx.font="10px ui-monospace,monospace";
    for(const n of nodes){const r=n.id===rootId?10:(n.group==="module"?4:6);
      ctx.fillStyle=col[n.group]||"#dbe4ee";ctx.beginPath();ctx.arc(n.x,n.y,r,0,7);ctx.fill();
      ctx.fillStyle="#8093a6";ctx.fillText((n.label||"").slice(0,26),n.x+r+3,n.y+3);}
    _raf=requestAnimationFrame(step);
  }
  step();
}
$("out").addEventListener("click",e=>{
  const card=e.target.closest(".pcard");if(!card)return;
  if(e.target.classList.contains("mine")){card.classList.toggle("is-mine");card.classList.remove("not-mine");}
  if(e.target.classList.contains("no")){card.classList.toggle("not-mine");card.classList.remove("is-mine");}
});
$("target").addEventListener("keydown",e=>{if(e.key==="Enter")$("run").click();});
</script>
</body></html>"""
