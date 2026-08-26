"""A tiny localhost web UI for Cypher, built on the standard library only.

A Bloomberg-terminal-style OSINT console: category sidebar, target command bar,
results panels (entity graph + correlation + findings + "is this you?" cards),
and a live analyst chat wired to Claude and grounded in the current scan.

Binds to 127.0.0.1 only. The Anthropic key loads from .env/environment.
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

CHAT_SYSTEM = (
    "You are CYPHER's OSINT analyst, chatting with the operator in a terminal about "
    "an open-source-intelligence investigation. Ground every answer strictly in the "
    "DATA below — if something isn't in the data, say so rather than inventing names, "
    "locations, or links. Be tight and practical, like a terminal. This is for "
    "authorized/defensive use (the operator's own footprint or targets they're "
    "permitted to assess): help them understand and reduce exposure. Do not help "
    "profile, locate, or build a dossier on an uninvolved private individual."
)


def _save_env_key(key: str) -> bool:
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
        return {"ok": False, "error": "Tick 'authorized' to continue."}
    if decision.requires_confirmation and looks_personal(target) and not payload.get("personal_ok"):
        return {"ok": False, "error": decision.reason, "needs_personal_ok": True}

    settings = Settings.load()
    key = (payload.get("api_key") or "").strip()
    if key:
        settings.anthropic_api_key = key
        if payload.get("save_key"):
            _save_env_key(key)
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


def chat(payload: dict) -> dict:
    settings = Settings.load()
    if not settings.anthropic_api_key:
        return {"ok": False, "error": "No Anthropic key in .env — add ANTHROPIC_API_KEY to chat."}
    raw_msgs = payload.get("messages") or []
    messages = [
        {"role": m.get("role", "user"), "content": str(m.get("content", ""))}
        for m in raw_msgs
        if m.get("content") and m.get("role") in ("user", "assistant")
    ][-12:]
    if not messages:
        return {"ok": False, "error": "empty message"}
    context = (payload.get("context") or "")[:12000] or "(no scan has been run yet)"
    system = f"{CHAT_SYSTEM}\n\n=== INVESTIGATION DATA ===\n{context}"
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        resp = client.messages.create(
            model=settings.model, max_tokens=1024, system=system, messages=messages
        )
        reply = "".join(b.text for b in resp.content if b.type == "text")
        return {"ok": True, "reply": reply or "(no response)"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


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

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/config":
            self._json(200, _config())
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path not in ("/scan", "/chat"):
            self._send(404, b"not found", "text/plain")
            return
        try:
            payload = self._read_json()
        except Exception as exc:
            self._json(400, {"ok": False, "error": f"bad request: {exc}"})
            return
        try:
            result = run_investigation(payload) if self.path == "/scan" else chat(payload)
        except Exception as exc:
            result = {"ok": False, "error": f"failed: {exc}"}
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
<title>CYPHER</title>
<style>
  :root{
    --bg:#000000;--panel:#0a0a0a;--panel2:#0f0f0f;--line:#242424;--line2:#333;
    --amber:#ff9e1b;--amber2:#ffbf5c;--text:#d8d2c4;--dim:#8a8272;--faint:#5a5648;
    --grn:#4ade80;--red:#ff5252;--blu:#5aa9ff;--vio:#b98cff;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--text);
    font:13px/1.5 "Consolas","Cascadia Mono",ui-monospace,monospace}
  ::-webkit-scrollbar{width:9px;height:9px}
  ::-webkit-scrollbar-thumb{background:#2a2a2a}
  ::-webkit-scrollbar-track{background:#000}
  .app{display:grid;grid-template-columns:184px 1fr 340px;grid-template-rows:auto auto 1fr;height:100vh}

  /* command bar */
  .cmd{grid-column:1/-1;display:flex;align-items:center;gap:0;background:#000;
    border-bottom:1px solid var(--amber)}
  .cmd .logo{padding:9px 16px;font-weight:700;letter-spacing:3px;color:var(--amber);
    border-right:1px solid var(--line)}
  .cmd .prompt{color:var(--amber);padding:0 8px 0 14px;user-select:none}
  .cmd input.tgt{flex:1;background:#000;border:0;color:var(--text);font:inherit;
    font-size:14px;padding:10px 4px;letter-spacing:1px;text-transform:none}
  .cmd input.tgt:focus{outline:none}
  .cmd .go{background:var(--amber);color:#000;border:0;font:inherit;font-weight:700;
    letter-spacing:2px;padding:0 22px;align-self:stretch;cursor:pointer}
  .cmd .go:hover{background:var(--amber2)} .cmd .go:disabled{opacity:.4;cursor:not-allowed}

  /* options strip */
  .opts{grid-column:1/-1;display:flex;gap:16px;align-items:center;background:var(--panel);
    border-bottom:1px solid var(--line);padding:6px 14px;color:var(--dim);font-size:11px}
  .opts label{display:flex;align-items:center;gap:5px}
  .opts input[type=checkbox]{accent-color:var(--amber)}
  .opts .num,.opts .vault{background:#000;border:1px solid var(--line);color:var(--text);
    font:inherit;font-size:11px;padding:3px 6px}
  .opts .num{width:38px;text-align:center}.opts .vault{width:150px}
  .opts .auth{color:var(--amber)}
  .opts .st{margin-left:auto;color:var(--dim)}
  .opts .st .on{color:var(--grn)} .opts .st .off{color:var(--red)}

  /* sidebar */
  .side{background:var(--panel);border-right:1px solid var(--line);overflow-y:auto}
  .side .hd{padding:8px 12px;color:var(--faint);font-size:10px;letter-spacing:2px;border-bottom:1px solid var(--line)}
  .navi{padding:7px 12px;display:flex;justify-content:space-between;cursor:pointer;color:var(--dim);
    border-bottom:1px solid #141414;font-size:12px;letter-spacing:.5px;user-select:none}
  .navi:hover{background:#141008;color:var(--text)}
  .navi.on{background:#1a1305;color:var(--amber);box-shadow:inset 3px 0 0 var(--amber)}
  .navi b{color:var(--faint);font-weight:400}
  .navi.on b{color:var(--amber2)}

  /* main */
  .main{overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:12px}
  .status{color:var(--dim);font-size:12px;min-height:16px}
  .spin{display:inline-block;width:11px;height:11px;border:2px solid #333;border-top-color:var(--amber);
    border-radius:50%;animation:s .7s linear infinite;vertical-align:-1px;margin-right:7px}
  @keyframes s{to{transform:rotate(360deg)}}
  .pan{border:1px solid var(--line);background:var(--panel)}
  .pan>.h{background:#000;color:var(--amber);padding:5px 11px;font-size:11px;letter-spacing:1.5px;
    border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
  .pan>.h .r{color:var(--faint);letter-spacing:.5px}
  .pan>.b{padding:11px}
  canvas#graph{width:100%;height:400px;display:block;background:#000}
  .summary{white-space:pre-wrap;font-size:12.5px;color:#cfc8b8}
  .mrow{border:1px solid var(--line);margin-top:7px}
  .mrow:first-child{margin-top:0}
  .mrow>.t{background:#000;padding:6px 10px;font-size:12px;color:var(--amber2);display:flex;
    justify-content:space-between;align-items:center}
  .badge{font-size:10px;padding:1px 7px;border:1px solid var(--line2);letter-spacing:.5px}
  .b-ok{color:var(--grn);border-color:#1e3a2a}.b-skip{color:var(--faint)}.b-err{color:var(--red);border-color:#3a1e1e}
  .f{padding:5px 10px;border-top:1px solid #161616;font-size:12px;color:#c2bbab}
  .f b{color:var(--text)}
  .sev{font-size:9px;padding:0 5px;margin-right:7px;letter-spacing:.5px}
  .s-high{background:var(--red);color:#000}.s-medium{background:var(--amber);color:#000}
  .s-low{background:var(--blu);color:#000}.s-info{background:#222;color:var(--dim)}
  a{color:var(--amber);text-decoration:none}

  .pgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px}
  .pc{display:flex;gap:10px;border:1px solid var(--line);padding:9px;background:#000}
  .pc.mine{border-color:#2a6b3a} .pc.no{opacity:.35}
  .pc img{width:50px;height:50px;object-fit:cover;background:#111;flex:none;border:1px solid var(--line)}
  .pc .m{flex:1;min-width:0}
  .pc .plat{color:var(--amber);font-size:10px;letter-spacing:1px}
  .pc .m b{display:block;font-size:12px}
  .pc .m p{margin:2px 0;color:var(--dim);font-size:11px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
  .pc .m a{font-size:10px;word-break:break-all}
  .pc .cf{display:flex;flex-direction:column;gap:5px;justify-content:center}
  .pc .cf button{background:#000;border:1px solid var(--line);color:var(--dim);font:inherit;font-size:10px;padding:3px 7px;cursor:pointer}
  .pc .cf .y:hover{border-color:#2a6b3a;color:var(--grn)}.pc .cf .n:hover{border-color:#6b2a2a;color:var(--red)}
  .empty{color:var(--faint);text-align:center;padding:50px 10px}

  /* chat */
  .chat{grid-row:2/-1;grid-column:3;border-left:1px solid var(--line);display:flex;flex-direction:column;background:var(--panel)}
  .chat .h{background:#000;color:var(--amber);padding:7px 12px;font-size:11px;letter-spacing:2px;border-bottom:1px solid var(--line)}
  .msgs{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:10px}
  .msg{font-size:12px;line-height:1.5}
  .msg .who{font-size:9px;letter-spacing:1px;margin-bottom:2px}
  .msg.u .who{color:var(--dim)} .msg.a .who{color:var(--amber)}
  .msg.u .txt{color:#cfc8b8}
  .msg.a .txt{color:var(--text);white-space:pre-wrap;border-left:2px solid var(--amber);padding-left:8px}
  .msg.u .txt{white-space:pre-wrap;border-left:2px solid var(--line2);padding-left:8px}
  .chat .in{border-top:1px solid var(--line);display:flex}
  .chat textarea{flex:1;background:#000;border:0;color:var(--text);font:inherit;font-size:12px;
    padding:9px;resize:none;height:52px}
  .chat textarea:focus{outline:none}
  .chat .snd{background:var(--amber);color:#000;border:0;font:inherit;font-weight:700;padding:0 14px;cursor:pointer}
  .chat .snd:hover{background:var(--amber2)}
  .chip{color:var(--faint);font-size:10px;padding:0 12px 8px}

  @media(max-width:900px){
    .app{grid-template-columns:1fr;grid-template-rows:auto auto auto 1fr}
    .side{display:none}
    .chat{grid-row:auto;grid-column:1;border-left:0;border-top:1px solid var(--line);height:340px}
  }
</style></head>
<body>
<div class="app">
  <div class="cmd">
    <span class="logo">CYPHER</span>
    <span class="prompt">TARGET&gt;</span>
    <input id="target" class="tgt" placeholder="domain / ip / email / url / username / phone" autofocus>
    <button id="run" class="go">RUN</button>
  </div>
  <div class="opts">
    <label><input type="checkbox" id="passive"> passive</label>
    <label>depth <input id="depth" class="num" value="1"></label>
    <label><input type="checkbox" id="obsidian"> obsidian</label>
    <input id="vault" class="vault" placeholder="vault path">
    <label class="auth"><input type="checkbox" id="authorized"> authorized</label>
    <span class="st" id="cfg"></span>
  </div>

  <div class="side">
    <div class="hd">MODULES</div>
    <div id="nav"></div>
  </div>

  <div class="main">
    <div class="status" id="status">Enter a target, tick authorized, hit RUN. Then ask the analyst on the right.</div>
    <div id="out"></div>
  </div>

  <div class="chat">
    <div class="h">◆ ANALYST CHAT</div>
    <div class="msgs" id="msgs"></div>
    <div class="chip" id="chatchip">Run a scan, then ask: "connect the dots", "which accounts are mine?", "what's my exposure?"</div>
    <div class="in">
      <textarea id="chatin" placeholder="ask the analyst…"></textarea>
      <button class="snd" id="send">SEND</button>
    </div>
  </div>
</div>
<script>
const $=id=>document.getElementById(id);
window.CTX="";
const CATS={
  "ALL":null,
  "DOMAIN":["dns_records","rdap_whois","crtsh_subdomains","wayback","http_fingerprint","whois","subfinder","amass","assetfinder","findomain","sublist3r","dnsrecon","dnsenum","fierce","dnstwist","gau","waybackurls","urlscan"],
  "EMAIL":["email_recon","breach_check","holehe","h8mail","mosint","socialscan"],
  "USERNAME":["username_sites","github_recon","sherlock","maigret","socialscan","telegram","instagram"],
  "INSTAGRAM":["instagram"],"TELEGRAM":["telegram"],"PHONE":["phone_info"],
  "IP":["ip_info","rdap_whois","bgpview","shodan_host","nmap","naabu","rustscan"],
  "WEB":["http_fingerprint","whatweb","wafw00f","httpx","katana","nuclei","nikto","gobuster","wpscan","sslscan"],
  "PORTS":["nmap","naabu","rustscan"],"BREACH":["breach_check","h8mail","holehe"]
};
let cat="ALL";
function nav(){const n=$("nav");n.innerHTML="";for(const k in CATS){const d=document.createElement("div");
  d.className="navi"+(k===cat?" on":"");d.innerHTML="<span>"+k+"</span><b>"+(CATS[k]?CATS[k].length:47)+"</b>";
  d.onclick=()=>{cat=k;nav();};n.appendChild(d);}}
nav();
fetch("/config").then(r=>r.json()).then(c=>{
  $("cfg").innerHTML="AI "+(c.has_key?"<span class=on>ONLINE</span>":"<span class=off>NO KEY</span>");
  if(c.default_vault)$("vault").value=c.default_vault;
}).catch(()=>{});

$("run").onclick=async()=>{
  const body={target:$("target").value,passive:$("passive").checked,authorized:$("authorized").checked,
    personal_ok:true,obsidian:$("obsidian").checked,vault:$("vault").value,
    depth:parseInt($("depth").value)||1,modules:CATS[cat]};
  if(!body.target){$("status").textContent="Enter a target.";return;}
  if(!body.authorized){$("status").textContent="Tick 'authorized' to continue.";return;}
  $("run").disabled=true;$("out").innerHTML="";
  $("status").innerHTML='<span class="spin"></span>RUNNING '+cat+' MODULES…';
  try{const r=await fetch("/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){$("status").textContent="✗ "+d.error;$("run").disabled=false;return;}
    $("status").innerHTML="✓ "+d.results.length+" MODULES · "+(d.ai_used?"CLAUDE":"DETERMINISTIC")+" · report saved"+(d.obsidian_path?" · OBSIDIAN":"");
    render(d);
  }catch(e){$("status").textContent="✗ "+e;}
  $("run").disabled=false;
};
function esc(s){return (s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function profiles(d){const o=[];for(const m of d.results)for(const f of (m.findings||[])){const x=f.data||{};
  if(x.platform&&(x.image||x.bio))o.push({platform:x.platform,name:f.detail,bio:x.bio||"",image:x.image||"",url:x.url||""});}return o;}
function render(d){
  // build chat context
  window.CTX="TARGET: "+d.target+" ("+d.target_type+")\\nSUMMARY:\\n"+d.summary+"\\n\\nFINDINGS:\\n"+
    d.results.flatMap(m=>(m.findings||[]).map(f=>"["+m.module+"] "+f.title+": "+f.detail)).join("\\n");
  $("chatchip").textContent="Analyst is loaded with this scan. Ask away.";
  let h="";
  const P=profiles(d);
  if(P.length){h+='<div class="pan"><div class="h">IS THIS YOU?<span class="r">'+P.length+' PROFILES</span></div><div class="b"><div class="pgrid">';
    for(const p of P){h+='<div class="pc">'+(p.image?'<img src="'+esc(p.image)+'" referrerpolicy="no-referrer" onerror="this.remove()">':'')+
      '<div class="m"><span class="plat">'+esc(p.platform)+'</span><b>'+esc(p.name)+'</b>'+(p.bio?'<p>'+esc(p.bio)+'</p>':'')+
      (p.url?'<a href="'+esc(p.url)+'" target="_blank" rel="noreferrer">'+esc(p.url)+'</a>':'')+
      '</div><div class="cf"><button class="y">MINE</button><button class="n">NOT</button></div></div>';}
    h+='</div></div></div>';}
  if(d.graph&&d.graph.nodes.length){h+='<div class="pan"><div class="h">ENTITY NETWORK<span class="r">'+d.graph.nodes.length+' NODES / '+d.graph.links.length+' LINKS</span></div><canvas id="graph" width="900" height="400"></canvas></div>';}
  h+='<div class="pan"><div class="h">CORRELATION<span class="r">'+(d.ai_used?"CLAUDE":"DETERMINISTIC")+'</span></div><div class="b summary">'+esc(d.summary)+'</div></div>';
  h+='<div class="pan"><div class="h">MODULE OUTPUT<span class="r">'+esc((d.plan||[]).join(" "))+'</span></div><div class="b">';
  for(const m of d.results){const cls=m.skipped?"b-skip":(m.ok?"b-ok":"b-err"),tg=m.skipped?"SKIP":(m.ok?"OK":"ERR");
    h+='<div class="mrow"><div class="t"><span>'+esc(m.module)+'</span><span class="badge '+cls+'">'+tg+'</span></div>';
    if(m.error)h+='<div class="f">'+esc(m.error)+'</div>';
    for(const f of m.findings)h+='<div class="f"><span class="sev s-'+f.severity+'">'+f.severity+'</span><b>'+esc(f.title)+'</b> '+esc(f.detail)+'</div>';
    h+='</div>';}
  h+='</div></div>';
  $("out").innerHTML=h;
  if(d.graph&&d.graph.nodes.length)drawGraph(d.graph);
}
$("out").addEventListener("click",e=>{const c=e.target.closest(".pc");if(!c)return;
  if(e.target.classList.contains("y")){c.classList.toggle("mine");c.classList.remove("no");}
  if(e.target.classList.contains("n")){c.classList.toggle("no");c.classList.remove("mine");}});

// ---- chat ----
const HIST=[];
function chatRender(){const m=$("msgs");m.innerHTML=HIST.map(x=>
  '<div class="msg '+(x.role==="user"?"u":"a")+'"><div class="who">'+(x.role==="user"?"YOU":"ANALYST")+'</div><div class="txt">'+esc(x.content)+'</div></div>').join("");
  m.scrollTop=m.scrollHeight;}
async function sendChat(){const t=$("chatin").value.trim();if(!t)return;
  $("chatin").value="";HIST.push({role:"user",content:t});chatRender();
  HIST.push({role:"assistant",content:"…"});chatRender();
  try{const r=await fetch("/chat",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({messages:HIST.filter(x=>x.content!=="…"),context:window.CTX})});
    const d=await r.json();HIST.pop();
    HIST.push({role:"assistant",content:d.ok?d.reply:("⚠ "+d.error)});chatRender();
  }catch(e){HIST.pop();HIST.push({role:"assistant",content:"⚠ "+e});chatRender();}}
$("send").onclick=sendChat;
$("chatin").addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendChat();}});
$("target").addEventListener("keydown",e=>{if(e.key==="Enter")$("run").click();});

// ---- graph ----
let _raf=null;
function drawGraph(g){const cv=$("graph");if(!cv)return;const ctx=cv.getContext("2d"),W=cv.width,H=cv.height;
  const col={domain:"#5aa9ff",ip:"#4ade80",email:"#ff9e1b",url:"#ffbf5c",username:"#b98cff",phone:"#4ade80",module:"#8a8272"};
  const root=g.nodes[0].id;
  const N=g.nodes.map(n=>({...n,x:W/2+(Math.random()-.5)*240,y:H/2+(Math.random()-.5)*240,vx:0,vy:0}));
  const ix={};N.forEach((n,i)=>ix[n.id]=i);const L=g.links.filter(l=>l.source in ix&&l.target in ix);
  if(_raf)cancelAnimationFrame(_raf);
  (function step(){
    for(let i=0;i<N.length;i++)for(let j=i+1;j<N.length;j++){const a=N[i],b=N[j];
      let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1,f=1500/(d*d);dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const l of L){const a=N[ix[l.source]],b=N[ix[l.target]];let dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1,f=(d-95)*.02;
      dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const n of N){n.vx+=(W/2-n.x)*.002;n.vy+=(H/2-n.y)*.002;n.vx*=.85;n.vy*=.85;n.x+=n.vx;n.y+=n.vy;}
    ctx.clearRect(0,0,W,H);ctx.strokeStyle="#242424";ctx.lineWidth=1;
    for(const l of L){const a=N[ix[l.source]],b=N[ix[l.target]];ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
    ctx.font="10px Consolas,monospace";
    for(const n of N){const r=n.id===root?9:(n.group==="module"?4:6);ctx.fillStyle=col[n.group]||"#d8d2c4";
      ctx.beginPath();ctx.arc(n.x,n.y,r,0,7);ctx.fill();ctx.fillStyle="#8a8272";ctx.fillText((n.label||"").slice(0,24),n.x+r+3,n.y+3);}
    _raf=requestAnimationFrame(step);
  })();
}
</script>
</body></html>"""
