"""A tiny localhost web UI for Cypher, built on the standard library only.

Serves one page: paste a target, tick authorization, hit Run. The Anthropic key
is built in — it loads from .env/environment automatically, and the UI can save a
pasted key back to .env so you never paste it again. Results can also be written
straight into an Obsidian vault.

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

    ctx = Context.create(settings)
    registry = discover()
    orch = Orchestrator(ctx, registry, use_ai=use_ai)
    obsidian_path = None
    try:
        inv = orch.investigate(target, depth=depth)
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
                    {"title": f.title, "detail": f.detail, "severity": f.severity.value}
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
  :root{--bg:#0a0e14;--card:#121820;--line:#1f2a37;--text:#d7e0ea;--muted:#7c8b9c;
        --accent:#39d0d8;--hi:#ff5d5d;--med:#ffb454;--low:#8ad4ff;--ok:#57d9a3}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
       font:15px/1.5 ui-monospace,"Cascadia Code",Consolas,monospace}
  .wrap{max-width:900px;margin:0 auto;padding:32px 20px 80px}
  h1{font-size:28px;letter-spacing:2px;margin:0 0 2px}
  h1 span{color:var(--accent)}
  .sub{color:var(--muted);margin:0 0 24px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:18px}
  label{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px;margin:12px 0 6px}
  input[type=text],input[type=password]{width:100%;background:#0c1219;border:1px solid var(--line);
       color:var(--text);border-radius:8px;padding:12px;font:inherit}
  input:focus{outline:none;border-color:var(--accent)}
  .hint{font-size:12px;color:var(--muted);margin:6px 0 0}
  .hint.good{color:var(--ok)}
  .row{display:flex;gap:20px;flex-wrap:wrap;align-items:center;margin-top:12px}
  .row label{margin:0;text-transform:none;letter-spacing:0;color:var(--text);font-size:14px;display:flex;align-items:center;gap:8px}
  button{margin-top:20px;background:var(--accent);color:#04252a;border:0;border-radius:8px;
       padding:14px 22px;font:inherit;font-weight:700;letter-spacing:1px;cursor:pointer;width:100%}
  button:disabled{opacity:.5;cursor:not-allowed}
  .gate{font-size:12px;color:var(--muted);border-left:2px solid var(--line);padding-left:12px;margin-top:8px}
  #status{margin-top:16px;color:var(--muted);min-height:22px}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line);border-top-color:var(--accent);
        border-radius:50%;animation:s .8s linear infinite;vertical-align:-2px;margin-right:8px}
  @keyframes s{to{transform:rotate(360deg)}}
  .summary{white-space:pre-wrap;background:#0c1219;border:1px solid var(--line);border-radius:8px;padding:16px;margin-top:12px}
  .mod{border:1px solid var(--line);border-radius:8px;margin-top:10px;overflow:hidden}
  .mod h3{margin:0;padding:10px 14px;background:#0e141c;font-size:14px;display:flex;justify-content:space-between}
  .tag{font-size:11px;padding:2px 8px;border-radius:20px}
  .t-ok{background:rgba(87,217,163,.15);color:var(--ok)} .t-skip{background:#0c1219;color:var(--muted)}
  .t-err{background:rgba(255,93,93,.15);color:var(--hi)}
  .f{padding:8px 14px;border-top:1px solid var(--line);font-size:13px}
  .f b{color:var(--text)} .sev{font-size:10px;text-transform:uppercase;padding:1px 6px;border-radius:4px;margin-right:8px}
  .s-high{background:var(--hi);color:#2a0000}.s-medium{background:var(--med);color:#2a1a00}
  .s-low{background:var(--low);color:#00202a}.s-info{background:var(--line);color:var(--muted)}
  a{color:var(--accent)}
</style></head>
<body><div class="wrap">
  <h1>CY<span>PH</span>ER</h1>
  <p class="sub">AI-orchestrated OSINT — paste a target, Claude does the rest.</p>

  <div class="card">
    <label>Target — domain, IP, email, URL, or username</label>
    <input id="target" type="text" placeholder="example.com" autofocus>

    <label>Anthropic API key</label>
    <input id="key" type="password" placeholder="sk-ant-...">
    <p class="hint" id="keyhint"></p>
    <div class="row">
      <label><input type="checkbox" id="savekey" checked> Remember this key (save to .env)</label>
    </div>

    <div class="row">
      <label><input type="checkbox" id="passive"> Passive only (no active probing)</label>
      <label>Depth <input type="text" id="depth" value="1" style="width:52px"> <span class="hint" style="margin:0">1 = target only, 2 = follow discoveries</span></label>
    </div>

    <div class="row">
      <label><input type="checkbox" id="obsidian"> Also save to Obsidian vault</label>
    </div>
    <input id="vault" type="text" placeholder="path to your Obsidian vault (e.g. /home/vio/Vault)">

    <div class="row">
      <label><input type="checkbox" id="authorized"> I am authorized to assess this target</label>
    </div>
    <p class="gate">Cypher gathers only open-source data. Use it on assets you own or are permitted to
      assess, or for your own defensive checks — not to profile private individuals.</p>

    <button id="run">RUN INVESTIGATION</button>
    <div id="status"></div>
  </div>

  <div id="out"></div>
</div>
<script>
const $=id=>document.getElementById(id);
let HAS_KEY=false;
fetch("/config").then(r=>r.json()).then(c=>{
  HAS_KEY=c.has_key;
  if(c.has_key){$("keyhint").textContent="✓ A key is already saved — leave this blank to use it.";$("keyhint").className="hint good";$("key").placeholder="using saved key";}
  else{$("keyhint").textContent="Paste once and tick Remember; blank = deterministic mode (no AI).";}
  if(c.default_vault){$("vault").value=c.default_vault;}
}).catch(()=>{});
$("run").onclick=async()=>{
  const body={target:$("target").value,api_key:$("key").value,save_key:$("savekey").checked,
    passive:$("passive").checked,authorized:$("authorized").checked,personal_ok:true,
    obsidian:$("obsidian").checked,vault:$("vault").value,depth:parseInt($("depth").value)||1};
  if(!body.target){$("status").textContent="Enter a target.";return;}
  if(!body.authorized){$("status").textContent="Tick the authorization box to continue.";return;}
  $("run").disabled=true;$("out").innerHTML="";
  $("status").innerHTML='<span class="spin"></span>Running modules and synthesizing…';
  try{
    const r=await fetch("/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){$("status").textContent="✗ "+d.error;$("run").disabled=false;return;}
    let msg="✓ Done — "+d.results.length+" modules. Report: "+(d.report_path||"reports/");
    if(d.obsidian_path)msg+=" | Obsidian: "+d.obsidian_path;
    if(d.saved_key)msg+=" | key saved";
    $("status").textContent=msg;
    render(d);
  }catch(e){$("status").textContent="✗ "+e;}
  $("run").disabled=false;
};
function esc(s){return (s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function render(d){
  let h="";
  if(d.graph&&d.graph.nodes.length){
    h+='<div class="card"><label>Entity graph — '+d.graph.nodes.length+' nodes / '+d.graph.links.length+' links</label>';
    h+='<canvas id="graph" width="860" height="440" style="width:100%;border:1px solid var(--line);border-radius:8px;background:#0c1219"></canvas></div>';
  }
  h+='<div class="card"><label>Intelligence summary'+(d.ai_used?" (Claude)":" (deterministic)")+'</label>';
  h+='<div class="summary">'+esc(d.summary)+'</div></div>';
  h+='<div class="card"><label>Module results — plan: '+esc((d.plan||[]).join(", "))+'</label>';
  for(const m of d.results){
    const cls=m.skipped?"t-skip":(m.ok?"t-ok":"t-err");
    const tag=m.skipped?"skip":(m.ok?"ok":"err");
    h+='<div class="mod"><h3><span>'+esc(m.module)+'</span><span class="tag '+cls+'">'+tag+'</span></h3>';
    if(m.error){h+='<div class="f">'+esc(m.error)+'</div>';}
    for(const f of m.findings){
      h+='<div class="f"><span class="sev s-'+f.severity+'">'+f.severity+'</span><b>'+esc(f.title)+'</b> — '+esc(f.detail)+'</div>';
    }
    h+='</div>';
  }
  h+='</div>';
  $("out").innerHTML=h;
  if(d.graph&&d.graph.nodes.length)drawGraph(d.graph);
}
let _raf=null;
function drawGraph(g){
  const cv=$("graph"); if(!cv)return;
  const ctx=cv.getContext("2d"),W=cv.width,H=cv.height;
  const col={domain:"#8ad4ff",ip:"#57d9a3",email:"#ffb454",url:"#39d0d8",username:"#c39bff",module:"#7c8b9c"};
  const rootId=g.nodes[0].id;
  const nodes=g.nodes.map(n=>({...n,x:W/2+(Math.random()-.5)*220,y:H/2+(Math.random()-.5)*220,vx:0,vy:0}));
  const idx={}; nodes.forEach((n,i)=>idx[n.id]=i);
  const links=g.links.filter(l=>l.source in idx&&l.target in idx);
  if(_raf)cancelAnimationFrame(_raf);
  function step(){
    for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i],b=nodes[j];let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1;
      const f=1400/(d*d);dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const l of links){const a=nodes[idx[l.source]],b=nodes[idx[l.target]];
      let dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1,f=(d-90)*0.02;
      dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const n of nodes){n.vx+=(W/2-n.x)*0.002;n.vy+=(H/2-n.y)*0.002;
      n.vx*=0.85;n.vy*=0.85;n.x+=n.vx;n.y+=n.vy;}
    ctx.clearRect(0,0,W,H);ctx.strokeStyle="#1f2a37";ctx.lineWidth=1;
    for(const l of links){const a=nodes[idx[l.source]],b=nodes[idx[l.target]];
      ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
    ctx.font="10px ui-monospace,monospace";
    for(const n of nodes){const r=n.id===rootId?10:(n.group==="module"?4:6);
      ctx.fillStyle=col[n.group]||"#d7e0ea";ctx.beginPath();ctx.arc(n.x,n.y,r,0,7);ctx.fill();
      ctx.fillStyle="#8ba0b4";ctx.fillText((n.label||"").slice(0,24),n.x+r+3,n.y+3);}
    _raf=requestAnimationFrame(step);
  }
  step();
}
$("target").addEventListener("keydown",e=>{if(e.key==="Enter")$("run").click();});
</script>
</body></html>"""
