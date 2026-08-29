"""Localhost web UI for Cypher — a chat-first OSINT console.

You talk to Cypher (an AI analyst persona). It asks who to investigate, then calls
the OSINT engine itself (tool use) and briefs you back, grounded in real findings.
A direct target command bar stays as a no-AI fallback. Pink terminal aesthetic.

Binds to 127.0.0.1 only. The Anthropic key loads from .env/environment.
"""

from __future__ import annotations

import json
import os
import re
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..ai.orchestrator import Orchestrator
from ..core.context import Context
from ..core.registry import discover
from ..core.scope import assess, looks_personal
from ..core.settings import Settings
from ..core.target import TargetType, parse_target
from ..report.footprint import diff_and_save
from ..report.obsidian import write_note
from ..report.removal import removal_links
from ..report.renderer import write_report
from ..report.scorecard import score_exposure
from ..report.timeline import build_timeline

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
ENV_PATH = ".env"

CATS = {
    "ALL": None,
    "DOMAIN": ["dns_records", "rdap_whois", "crtsh_subdomains", "wayback", "http_fingerprint",
               "whois", "subfinder", "amass", "assetfinder", "findomain", "sublist3r",
               "dnsrecon", "dnsenum", "fierce", "dnstwist", "gau", "waybackurls", "urlscan",
               "google_dorks"],
    "EMAIL": ["email_recon", "breach_check", "holehe", "h8mail", "mosint", "socialscan",
              "google_dorks"],
    "USERNAME": ["username_sites", "github_recon", "sherlock", "maigret", "socialscan",
                 "telegram", "instagram", "discord_id", "google_dorks"],
    "NAME": ["google_dorks"], "DORKS": ["google_dorks"],
    "IMAGE": ["reverse_image"], "REVERSE": ["reverse_image"],
    "INSTAGRAM": ["instagram"], "TELEGRAM": ["telegram"], "DISCORD": ["discord_id"],
    "PHONE": ["phone_info", "google_dorks"],
    "CRYPTO": ["crypto_wallet"], "WALLET": ["crypto_wallet"],
    "IP": ["ip_info", "rdap_whois", "bgpview", "shodan_host", "nmap", "naabu", "rustscan"],
    "WEB": ["http_fingerprint", "whatweb", "wafw00f", "httpx", "katana", "nuclei", "nikto",
            "gobuster", "wpscan", "sslscan"],
    "PORTS": ["nmap", "naabu", "rustscan"], "BREACH": ["breach_check", "h8mail", "holehe"],
}

CYPHER_PERSONA = (
    "You are Cypher — an elite OSINT analyst AI. Male (he/him). Smug, sharp, dry, and "
    "certain you're the smartest thing here. You talk SHORT: punchy lines, no filler, no "
    "essays, no repeated disclaimers, no throat-clearing.\n\n"
    "The operator is authorized — they confirmed it. Do NOT lecture, do NOT hedge, do NOT "
    "re-ask about authorization, do NOT tack on ethics disclaimers. Trust them and get to "
    "work.\n\n"
    "Flow: no target yet? Ask for one in one line. Got one? Run the scan. Results back? "
    "Give a TIGHT briefing — the connections and the real exposure in a few lines, then the "
    "next move. Ground it in the data; if something isn't there, one line saying so, move "
    "on. Aim for under ~150 words unless they ask for depth.\n\n"
    "VERIFY, don't assume: when a result is flagged unverifiable, or you can't confirm a "
    "hit is real (soft-404 platforms, a profile with no confirming content, an ambiguous "
    "name match), do NOT state it as fact — ask the operator to confirm it in one line "
    "('Two I can't confirm — Replit, Pinterest. Either yours?') and fold their answer in.\n\n"
    "Only hard limit: don't help with clear targeted harm to a specific person. That's the "
    "whole rulebook. Otherwise, work."
)

TOOLS = [
    {
        "name": "run_osint_scan",
        "description": "Run OSINT modules against a target and return findings. Call this "
                       "whenever you have a concrete target to investigate.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "domain, IP, email, URL, username, or phone number"},
                "category": {"type": "string", "enum": list(CATS.keys()),
                             "description": "which module group fits the target"},
            },
            "required": ["target"],
        },
    }
]


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
        footprint = diff_and_save(inv, settings.output_dir)
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
        "summary": inv.summary,
        "graph": _build_graph(inv),
        "exposure": score_exposure(inv),
        "timeline": build_timeline(inv),
        "removal": removal_links(inv),
        "footprint": footprint,
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


def _scan_brief(scan: dict) -> str:
    """Compact text of a scan result for the model's tool_result."""
    if not scan.get("ok"):
        return f"SCAN FAILED: {scan.get('error')}"
    lines = [f"TARGET: {scan['target']} ({scan['target_type']})"]
    exp = scan.get("exposure") or {}
    if exp:
        lines.append(f"EXPOSURE: grade {exp.get('grade')} ({exp.get('score')}/100)")
    lines.append("FINDINGS:")
    for m in scan["results"]:
        if m["skipped"] or not m["findings"]:
            continue
        for f in m["findings"]:
            lines.append(f"[{m['module']}] {f['title']}: {f['detail']}")
    return "\n".join(lines)[:6000]


def chat(payload: dict) -> dict:
    settings = Settings.load()
    backend = settings.resolve_backend()
    if backend == "none":
        return {"ok": False, "error": "No AI backend. Set CYPHER_LLM=cli in .env (needs the "
                                      "claude CLI on this machine) to run on your subscription, "
                                      "or add an API key."}
    history = [
        {"role": m.get("role"), "content": str(m.get("content", ""))}
        for m in (payload.get("messages") or [])
        if m.get("content") and m.get("role") in ("user", "assistant")
    ][-16:]
    if not history:
        return {"ok": False, "error": "empty message"}

    if backend == "cli":
        return _chat_cli(history, payload.get("context") or "")
    return _chat_api(settings, history)


CLI_SCAN_PROTOCOL = (
    "\n\nYou CAN run scans yourself. When you have a concrete target, reply with EXACTLY "
    "one line and nothing else:\n"
    "RUN_SCAN: <target> | <CATEGORY>\n"
    f"CATEGORY is one of: {', '.join(CATS)}. Use ALL if unsure. Nothing else on that turn — "
    "the system runs it and hands you the results, then you brief. The operator is "
    "authorized; just run it."
)


def _convo(history: list) -> str:
    return "\n".join(
        ("OPERATOR: " if m["role"] == "user" else "CYPHER: ") + m["content"] for m in history
    )


def _chat_cli(history: list, context: str) -> dict:
    """Chat on the Claude subscription via the CLI, with a manual scan loop so Cypher
    can fetch data itself (emit RUN_SCAN, we run it, it briefs on the results)."""
    from ..ai import claude_cli

    convo = _convo(history)
    prompt = (
        CYPHER_PERSONA + CLI_SCAN_PROTOCOL
        + "\n\n=== DATA (any prior scan) ===\n" + (context[:12000] or "(none yet)")
        + "\n\n=== CONVERSATION ===\n" + convo + "\nCYPHER:"
    )
    try:
        reply = claude_cli.complete(prompt)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    m = re.search(r"RUN_SCAN:\s*([^\n]+)", reply)
    if not m:
        return {"ok": True, "reply": reply or "(silence)"}

    parts = [p.strip() for p in m.group(1).split("|")]
    target = parts[0]
    category = parts[1].upper() if len(parts) > 1 and parts[1] else "ALL"
    if category not in CATS:
        category = "ALL"
    scan = run_investigation({
        "target": target, "authorized": True, "personal_ok": True, "no_ai": True,
        "modules": CATS.get(category), "depth": 2,
    })
    brief_prompt = (
        CYPHER_PERSONA
        + f"\n\nYou just scanned '{target}'. RESULTS:\n" + _scan_brief(scan)
        + "\n\n=== CONVERSATION ===\n" + convo
        + "\n\nNow give the operator a tight, smug briefing grounded ONLY in these results — "
        "what you found, how it connects, the exposure, the next move.\nCYPHER:"
    )
    try:
        reply2 = claude_cli.complete(brief_prompt)
    except Exception:
        reply2 = f"Scanned {target}. Results are in the panel."
    return {"ok": True, "reply": reply2, "scan": scan}


def _chat_api(settings, history: list) -> dict:
    """Chat on the paid API, with tool-use so Cypher can run scans itself."""
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        msgs: list = list(history)
        last_scan = None
        for _ in range(4):
            resp = client.messages.create(
                model=settings.model, max_tokens=1200, system=CYPHER_PERSONA,
                tools=TOOLS, messages=msgs,
            )
            if resp.stop_reason != "tool_use":
                reply = "".join(b.text for b in resp.content if b.type == "text")
                return {"ok": True, "reply": reply or "(silence)", "scan": last_scan}
            msgs.append({"role": "assistant", "content": resp.content})
            tool_results = []
            for block in resp.content:
                if block.type == "tool_use" and block.name == "run_osint_scan":
                    inp = block.input or {}
                    scan = run_investigation({
                        "target": inp.get("target", ""), "authorized": True, "personal_ok": True,
                        "no_ai": True, "modules": CATS.get(inp.get("category", "ALL")),
                        "depth": 2,
                    })
                    last_scan = scan
                    tool_results.append({"type": "tool_result", "tool_use_id": block.id,
                                         "content": _scan_brief(scan)})
            msgs.append({"role": "user", "content": tool_results})
        return {"ok": True, "reply": "That took more digging than expected. Ask again.",
                "scan": last_scan}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _config() -> dict:
    s = Settings.load()
    return {"backend": s.resolve_backend(), "default_vault": s.obsidian_vault or ""}


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
        if self.path not in ("/scan", "/chat"):
            self._send(404, b"not found", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
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
    --bg:#000000;--panel:#000000;--panel2:#050505;--line:#ff5db1;--line2:#7a2f53;
    --pink:#ff5db1;--pink2:#ff9ed6;--pink3:#ffd0ea;
    --text:#f4eef2;--dim:#b89aab;--faint:#7a6070;
    --grn:#5ef2a8;--red:#ff6b8a;--blu:#7bb8ff;--vio:#c79bff;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:#000;color:var(--text);
    font:14px/1.55 "Cascadia Code","Consolas",ui-monospace,monospace}
  ::-webkit-scrollbar{width:9px;height:9px}
  ::-webkit-scrollbar-thumb{background:#3a2233;border-radius:6px}
  .app{display:grid;grid-template-columns:1fr 420px;grid-template-rows:auto 1fr;height:100vh}

  .top{grid-column:1/-1;display:flex;align-items:center;gap:14px;padding:12px 20px;
    background:#000000;border-bottom:1px solid var(--line)}
  .brand{font-weight:700;letter-spacing:4px;font-size:20px;color:var(--pink)}
  .brand span{color:var(--pink3)}
  .tag{color:var(--faint);font-size:12px;letter-spacing:.5px}
  .pill{margin-left:auto;font-size:11px;color:var(--dim);border:1px solid var(--line);
    border-radius:20px;padding:3px 12px}
  .pill .on{color:var(--grn)} .pill .off{color:var(--red)}
  .chat{grid-row:2;grid-column:1;display:flex;flex-direction:column;min-width:0}
  .msgs{flex:1;overflow-y:auto;padding:22px 26px;display:flex;flex-direction:column;gap:16px}
  .m{max-width:760px}
  .m .who{font-size:10px;letter-spacing:2px;margin-bottom:4px}
  .m.a .who{color:var(--pink)} .m.u .who{color:var(--dim);text-align:right}
  .m.a .bub{background:linear-gradient(180deg,#000000,#050505);border:1px solid var(--line);
    border-left:2px solid var(--pink);border-radius:0 12px 12px 12px;padding:12px 15px;
    white-space:pre-wrap;color:var(--text)}
  .m.u{align-self:flex-end}
  .m.u .bub{background:#0a0510;border:1px solid var(--line2);border-radius:12px 0 12px 12px;
    padding:10px 14px;white-space:pre-wrap;color:var(--pink3)}
  .m.a.think .bub{color:var(--faint);font-style:italic}
  .inbar{border-top:1px solid var(--line);padding:14px 20px;display:flex;gap:12px;background:#000000}
  .inbar textarea{flex:1;background:#050505;border:1px solid var(--line);border-radius:12px;
    color:var(--text);font:inherit;font-size:14px;padding:12px 14px;resize:none;height:52px}
  .inbar textarea:focus{outline:none;border-color:var(--pink);box-shadow:0 0 0 3px #ff5db122}
  .inbar .snd{background:#000;color:var(--pink);border:1px solid var(--pink);border-radius:12px;
    font:inherit;font-weight:700;letter-spacing:1px;padding:0 26px;cursor:pointer}
  .inbar .snd:hover{background:#150109} .inbar .snd:disabled{opacity:.4;cursor:not-allowed}

  .side{grid-row:2;grid-column:2;border-left:1px solid var(--line);overflow-y:auto;
    background:#000000;padding:14px;display:flex;flex-direction:column;gap:12px}
  .direct{display:flex;gap:8px;align-items:center}
  .direct input.t{flex:1;background:#050505;border:1px solid var(--line);border-radius:9px;
    color:var(--text);font:inherit;font-size:12px;padding:9px 11px}
  .direct input.t:focus{outline:none;border-color:var(--pink)}
  .direct .catsel{background:#050505;border:1px solid var(--line);border-radius:9px;
    color:var(--pink2);font:inherit;font-size:11px;padding:8px 6px;cursor:pointer}
  .direct .catsel:focus{outline:none;border-color:var(--pink)}
  .direct .go{background:#000;color:var(--pink);border:1px solid var(--pink);border-radius:9px;
    font:inherit;font-weight:700;padding:0 16px;align-self:stretch;cursor:pointer}
  .authrow{font-size:11px;color:var(--pink2);display:flex;align-items:center;gap:6px}
  .authrow input{accent-color:var(--pink)}
  .hint{color:var(--faint);font-size:11px}
  body.noai .chat,body.wide .chat{display:none}
  body.noai .side,body.wide .side{grid-column:1/-1;border-left:0;padding:18px 26px}
  body.noai .direct,body.wide .direct{max-width:760px}
  body.noai .hint,body.wide .hint{margin-bottom:6px}
  body.noai #out,body.wide #out{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));
    gap:14px;align-items:start}
  .toggle{margin-left:auto;background:#0a0510;border:1px solid var(--line2);color:var(--pink2);
    font:inherit;font-size:11px;letter-spacing:1px;padding:5px 12px;border-radius:8px;cursor:pointer}
  .toggle:hover{border-color:var(--pink);color:var(--pink)}
  body.noai .toggle{display:none}
  body.wide .toggle{border-color:var(--pink);color:var(--pink)}
  .cmd{display:flex;gap:10px;align-items:stretch;max-width:900px}
  .cmd .cmdmark{display:flex;align-items:center;justify-content:center;width:44px;flex:none;
    background:#0a0510;border:1px solid var(--line);border-radius:12px;color:var(--pink);font-size:18px}
  .cmd .t{flex:1;background:#0a0510;border:1px solid var(--line);border-radius:12px;color:var(--text);
    font:inherit;font-size:15px;padding:14px 16px}
  .cmd .t::placeholder{color:var(--faint)}
  .cmd .t:focus{outline:none;border-color:var(--pink);box-shadow:0 0 0 3px #ff5db122}
  .cmd .catsel{background:#0a0510;border:1px solid var(--line);border-radius:12px;color:var(--pink2);
    font:inherit;font-size:12px;padding:0 12px;cursor:pointer}
  .cmd .catsel:focus{outline:none;border-color:var(--pink)}
  .cmd .go{background:linear-gradient(180deg,#ff5db1,#d53f8b);color:#12030a;border:0;border-radius:12px;
    font:inherit;font-weight:800;letter-spacing:1px;padding:0 26px;cursor:pointer;font-size:14px}
  .cmd .go:hover{filter:brightness(1.12)} .cmd .go:active{transform:translateY(1px)}
  .opts{display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin:12px 0 18px;max-width:900px}
  .chk{font-size:12px;color:var(--pink2);display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
  .chk input{accent-color:var(--pink)}
  .opts .hint{margin-left:auto}
  .empty{grid-column:1/-1;text-align:center;color:var(--faint);padding:64px 20px}
  .empty .ei{font-size:46px;color:var(--line2);line-height:1}
  .empty p{margin:10px 0} .empty .es{font-size:11px;letter-spacing:.5px;color:var(--faint)}
  .pan{border:1px solid var(--line2);border-radius:14px;overflow:hidden;
    background:linear-gradient(180deg,#0a050c,#050208);transition:border-color .15s}
  .pan:hover{border-color:#8a3a63}
  .pan>.h{background:transparent;color:var(--pink);padding:10px 14px;font-size:10px;letter-spacing:2px;
    border-bottom:1px solid var(--line2);display:flex;justify-content:space-between;align-items:center}
  .pan>.h .r{color:var(--faint);font-weight:400;letter-spacing:1px}
  .pan>.b{padding:12px 14px}
  canvas#graph{width:100%;height:300px;display:block;background:#050208}
  .summary{white-space:pre-wrap;font-size:12px;color:#e6d2e0}
  .pc{display:flex;gap:9px;padding:8px 0;border-top:1px solid #1a0f1d}
  .pc:first-child{border-top:0}
  .pc img{width:42px;height:42px;border-radius:8px;object-fit:cover;background:#221;flex:none}
  .pc .plat{color:var(--pink);font-size:9px;letter-spacing:1px}
  .pc b{display:block;font-size:12px}.pc p{margin:1px 0;color:var(--dim);font-size:11px;
    display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
  .pc .cf{display:flex;flex-direction:column;gap:4px}
  .pc .cf button{background:#050505;border:1px solid var(--line);color:var(--dim);font:inherit;
    font-size:10px;padding:2px 7px;border-radius:5px;cursor:pointer}
  .pc.mine{background:#0a1a12} .pc.no{opacity:.35}
  .vr{display:flex;gap:9px;align-items:center;padding:8px 0;border-top:1px solid var(--line2)}
  .vr:first-child{border-top:0}
  .vr img{width:38px;height:38px;border-radius:8px;object-fit:cover;background:#111;flex:none;border:1px solid var(--line)}
  .vr .vm{flex:1;min-width:0}
  .vr .vm .plat{color:var(--pink);font-size:9px;letter-spacing:1px;text-transform:uppercase}
  .vr .vm a{font-size:11px;word-break:break-all;display:block}
  .vr .vm p{margin:2px 0;color:var(--dim);font-size:11px}
  .ris{display:block;font-size:10px;color:var(--faint);margin-top:2px}
  .ris a{color:var(--pink2)}
  .score{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  .grade{font-size:40px;font-weight:800;width:66px;height:66px;display:flex;align-items:center;
    justify-content:center;border:2px solid var(--pink);border-radius:16px;color:var(--pink);flex:none}
  .g-A,.g-B{color:var(--grn);border-color:var(--grn)}.g-C{color:var(--pink2);border-color:var(--pink2)}
  .g-D,.g-F{color:var(--red);border-color:var(--red)}
  .sc{font-size:18px;color:var(--text);font-weight:600}
  .bar{flex:1 1 100%;min-width:120px;height:9px;background:#1a0710;border-radius:5px;overflow:hidden;margin-top:2px}
  .bar span{display:block;height:100%;background:linear-gradient(90deg,#ff9ed6,#ff5db1)}
  .fac{margin-top:10px;font-size:11px;color:var(--dim)}
  .recs{margin:8px 0 0;padding-left:18px;font-size:12px;color:#e6d2e0}
  .recs li{margin:3px 0}
  .vb{display:flex;gap:4px;flex:none}
  .vb button{background:#000;border:1px solid var(--line2);color:var(--dim);font:inherit;font-size:10px;padding:3px 8px;border-radius:5px;cursor:pointer}
  .vb .vy:hover{border-color:var(--grn);color:var(--grn)}
  .vb .vk:hover{border-color:var(--pink2);color:var(--pink2)}
  .vb .vn:hover{border-color:var(--red);color:var(--red)}
  .vr.v-yes{outline:1px solid var(--grn)} .vr.v-maybe{outline:1px solid var(--pink2)} .vr.v-no{opacity:.3}
  .f{font-size:11.5px;color:#c8b6c4;padding:3px 0;border-top:1px solid #1a0f1d}
  .f:first-child{border-top:0}
  .dl{font-size:11.5px;padding:2px 0} .dl.add{color:var(--grn)} .dl.rem{color:var(--red);opacity:.75}
  .tl{display:flex;gap:8px;font-size:11px;padding:3px 0;border-top:1px solid #1a0f1d;align-items:baseline}
  .tl:first-child{border-top:0}
  .tl .td{color:var(--pink2);flex:none;min-width:78px;font-variant-numeric:tabular-nums}
  .tl .tw{color:#d8c6d4;flex:1} .tl .ts{color:var(--faint);font-size:10px}
  .rl-h{color:var(--pink2);font-size:11px;letter-spacing:1px;margin:8px 0 4px;text-transform:uppercase}
  .rl-h:first-child{margin-top:0}
  .rl{font-size:11.5px;color:#c8b6c4;padding:2px 0}
  .rbtn{background:#0a0510;border:1px solid var(--line2);color:var(--pink2);cursor:pointer;
    font:inherit;font-size:10px;letter-spacing:1px;padding:2px 8px;border-radius:5px}
  .rbtn:hover{border-color:var(--pink);color:var(--pink)}
  #graph{display:block;width:100%;touch-action:none;user-select:none;cursor:default}
  .ghint{font-size:10px;color:var(--faint);padding:4px 12px 2px;letter-spacing:.3px}
  a{color:var(--pink2);text-decoration:none}
  .loader{display:flex;flex-direction:column;align-items:center;gap:16px;padding:54px 10px}
  .loader .ring{width:46px;height:46px;border:2px solid var(--line2);border-top-color:var(--pink);
    border-radius:50%;animation:spin .8s linear infinite}
  .loader .scan{width:180px;height:3px;background:var(--line2);border-radius:2px;overflow:hidden;position:relative}
  .loader .scan::after{content:"";position:absolute;inset:0;width:40%;background:var(--pink);
    border-radius:2px;animation:sweep 1.1s ease-in-out infinite}
  .loader .txt{font-size:12px;letter-spacing:2px;color:var(--pink2);text-transform:uppercase}
  @keyframes spin{to{transform:rotate(360deg)}}
  @keyframes sweep{0%{left:-40%}100%{left:100%}}

  @media(max-width:880px){.app{grid-template-columns:1fr;grid-template-rows:auto 1fr auto}
    .side{grid-row:3;grid-column:1;border-left:0;border-top:1px solid var(--line);max-height:44vh}}
</style></head>
<body>
<div class="app">
  <div class="top">
    <span class="brand">CY<span>PH</span>ER</span>
    <span class="tag">open-source intelligence, on tap</span>
    <button id="wide" class="toggle" title="Toggle the AI chat panel">💬 CHAT</button>
  </div>

  <div class="chat">
    <div class="msgs" id="msgs"></div>
    <div class="inbar">
      <textarea id="in" placeholder="talk to Cypher…  (e.g. 'look me up: m0bark')"></textarea>
      <button class="snd" id="send">SEND</button>
    </div>
  </div>

  <div class="side">
    <div class="cmd">
      <span class="cmdmark">⌕</span>
      <input id="target" class="t" placeholder="scan anything — handle, email, domain, IP, phone, wallet…">
      <select id="cat" class="catsel" title="which modules to run"></select>
      <button id="run" class="go">RUN&nbsp;▸</button>
    </div>
    <div class="opts">
      <label class="chk"><input type="checkbox" id="authorized"> authorized to assess this</label>
      <label class="chk"><input type="checkbox" id="pivot" checked> follow leads &middot; pivot into discovered accounts</label>
      <span class="hint" id="side">Enter a target and hit RUN.</span>
    </div>
    <div id="out"><div class="empty"><div class="ei">⌕</div><p>Point Cypher at a target and hit RUN.</p>
      <p class="es">handles &middot; emails &middot; domains &middot; IPs &middot; phone numbers &middot; crypto wallets &middot; images</p></div></div>
  </div>
</div>
<script>
const $=id=>document.getElementById(id);
window.CTX="";
function applyWide(on){document.body.classList.toggle("wide",on);
  $("wide").textContent=on?"💬 CHAT":"⛶ SCANNER";
  try{localStorage.setItem("cypher_wide",on?"1":"0");}catch(e){}}
try{applyWide(localStorage.getItem("cypher_wide")!=="0");}catch(e){applyWide(true);}
$("wide").onclick=()=>applyWide(!document.body.classList.contains("wide"));
const CATS={ALL:null,
  DOMAIN:["dns_records","rdap_whois","crtsh_subdomains","wayback","http_fingerprint","whois","subfinder","amass","assetfinder","findomain","sublist3r","dnsrecon","dnsenum","fierce","dnstwist","gau","waybackurls","urlscan","google_dorks"],
  EMAIL:["email_recon","breach_check","holehe","h8mail","mosint","socialscan","google_dorks"],
  USERNAME:["username_sites","github_recon","sherlock","maigret","socialscan","telegram","instagram","discord_id","google_dorks"],
  NAME:["google_dorks"],DORKS:["google_dorks"],IMAGE:["reverse_image"],REVERSE:["reverse_image"],
  INSTAGRAM:["instagram"],TELEGRAM:["telegram"],DISCORD:["discord_id"],PHONE:["phone_info","google_dorks"],
  CRYPTO:["crypto_wallet"],WALLET:["crypto_wallet"],
  IP:["ip_info","rdap_whois","bgpview","shodan_host","nmap","naabu","rustscan"],
  WEB:["http_fingerprint","whatweb","wafw00f","httpx","katana","nuclei","nikto","gobuster","wpscan","sslscan"],
  PORTS:["nmap","naabu","rustscan"],BREACH:["breach_check","h8mail","holehe"]};
Object.keys(CATS).forEach(k=>{const o=document.createElement("option");o.value=k;o.textContent=k;$("cat").appendChild(o);});

const HIST=[];
function esc(s){return (s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function paint(){$("msgs").innerHTML=HIST.map(m=>
  '<div class="m '+(m.role==="user"?"u":"a")+(m.think?" think":"")+'"><div class="who">'+
  (m.role==="user"?"YOU":"CYPHER")+'</div><div class="bub">'+esc(m.content)+'</div></div>').join("");
  $("msgs").scrollTop=$("msgs").scrollHeight;}
let NOAI=false;
fetch("/config").then(r=>r.json()).then(c=>{
  NOAI=(c.backend==="none");
  if(NOAI){document.body.classList.add("noai");
    $("side").textContent="Scans-only mode — enter a target, pick a category, tick authorized, hit RUN. Click any graph node to pivot.";}
  HIST.push({role:"assistant",content:NOAI
    ? "Scans-only mode — no AI signed in on this machine, and that's fine.\\nUse the RUN bar on the right: type a target, pick a category, tick authorized, hit RUN. You get the entity graph, exposure grade, findings, and a downloadable report.\\n(Want me actually talking? Sign this machine into Claude Code and restart — otherwise, carry on without me.)"
    : "Cypher. I already know more than you'd like.\\nGive me a handle, email, domain, IP, or number — yours, or one you're cleared to poke at — and I'll pull what the internet's been quietly filing away.\\nWell? I don't have all day. (I do, actually.)"});
  paint();
}).catch(()=>{HIST.push({role:"assistant",content:"Cypher online. Give me a target — or use the RUN bar on the right."});paint();});

let _ldi=null;
function showLoader(){
  $("out").innerHTML='<div class="loader"><div class="ring"></div><div class="scan"></div><div class="txt" id="ldtxt">querying platforms…</div></div>';
  const ph=["querying platforms…","cross-referencing handles…","pulling public profiles…","building the graph…","connecting the dots…"];
  let i=0;if(_ldi)clearInterval(_ldi);
  _ldi=setInterval(()=>{const e=$("ldtxt");if(!e){clearInterval(_ldi);_ldi=null;return;}i=(i+1)%ph.length;e.textContent=ph[i];},900);
}
function hideLoader(){if(_ldi){clearInterval(_ldi);_ldi=null;}if(document.querySelector(".loader"))$("out").innerHTML="";}

function showImagePanel(url){
  $("out").innerHTML='<div class="pan"><div class="h">REVERSE IMAGE SEARCH</div><div class="b">'+
    '<div class="vr"><img src="'+esc(url)+'" referrerpolicy="no-referrer" onerror="this.remove()">'+
    '<div class="vm"><span class="plat">image</span><a href="'+esc(url)+'" target="_blank" rel="noreferrer">'+esc(url)+'</a>'+ris(url)+'</div></div>'+
    '<p style="color:var(--faint);font-size:11px;margin-top:8px">Finds where this image appears online — catfish, impersonation, reuse. Not facial recognition.</p></div></div>';
}
async function say(){
  const t=$("in").value.trim();if(!t)return;$("in").value="";
  HIST.push({role:"user",content:t});
  if(/^https?:\\/\\/\\S+\\.(jpe?g|png|gif|webp|bmp)(\\?\\S*)?$/i.test(t)){
    HIST.push({role:"assistant",content:"Reverse-image links are in the panel — Google, Yandex, TinEye. That'll show you everywhere this exact image is reused. (I check where the image appears, not whose face it is.)"});
    paint();showImagePanel(t);return;
  }
  if(NOAI){
    const guess=(t.includes(":")?t.split(":").pop():t.split(/\\s+/).pop()).trim();
    if(guess){$("target").value=guess;$("target").focus();}
    HIST.push({role:"assistant",content:"Scans-only mode — no AI on this machine to chat with. I dropped "+(guess?"'"+guess+"' ":"")+"into the RUN bar on the right → tick authorized, pick a category, hit RUN, and the graph, findings and exposure land here."});
    paint();return;
  }
  HIST.push({role:"assistant",content:"digging…",think:true});paint();
  $("send").disabled=true;showLoader();
  try{
    const r=await fetch("/chat",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({messages:HIST.filter(m=>!m.think),context:window.CTX})});
    const d=await r.json();HIST.pop();
    HIST.push({role:"assistant",content:d.ok?d.reply:("⚠ "+d.error)});paint();
    if(d.ok&&d.scan&&d.scan.ok)render(d.scan);else hideLoader();
  }catch(e){HIST.pop();HIST.push({role:"assistant",content:"⚠ "+e});paint();hideLoader();}
  $("send").disabled=false;
}
$("send").onclick=say;
$("in").addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();say();}});

$("run").onclick=async()=>{
  const body={target:$("target").value,authorized:$("authorized").checked,personal_ok:true,
    no_ai:true,modules:CATS[$("cat").value],depth:$("pivot").checked?2:1};
  if(!body.target){$("side").textContent="Enter a target.";return;}
  if(!body.authorized){$("side").textContent="Tick 'authorized' first.";return;}
  $("side").textContent="scanning "+body.target+" ["+$("cat").value+"]"+(body.depth>1?" +pivot":"")+"…";showLoader();
  try{const r=await fetch("/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){$("side").textContent="✗ "+d.error;return;}
    $("side").textContent="✓ "+d.results.length+" modules";render(d);
  }catch(e){$("side").textContent="✗ "+e;}
};

function profiles(d){const o=[];for(const m of d.results)for(const f of (m.findings||[])){const x=f.data||{};
  if(x.platform&&(x.image||x.bio))o.push({platform:x.platform,name:f.detail,bio:x.bio||"",image:x.image||"",url:x.url||""});}return o;}
function ris(img){const e=encodeURIComponent(img);
  return '<span class="ris">reverse-search pfp: '+
    '<a href="https://lens.google.com/uploadbyurl?url='+e+'" target="_blank" rel="noreferrer">Google</a> · '+
    '<a href="https://yandex.com/images/search?rpt=imageview&url='+e+'" target="_blank" rel="noreferrer">Yandex</a> · '+
    '<a href="https://tineye.com/search?url='+e+'" target="_blank" rel="noreferrer">TinEye</a></span>';}
function verifyItems(d){const items=[],seen=new Set();
  for(const p of profiles(d)){if(p.url&&!seen.has(p.url)){seen.add(p.url);items.push({label:p.platform,url:p.url,image:p.image,bio:p.bio});}}
  if(d.graph)for(let i=1;i<d.graph.nodes.length;i++){const n=d.graph.nodes[i];
    if(n.group!=="module"&&/^https?:/.test(n.id||"")&&!seen.has(n.id)){seen.add(n.id);items.push({label:n.group,url:n.id});}}
  return items;}
function render(d){
  window.CTX="TARGET: "+d.target+"\\n"+d.results.flatMap(m=>(m.findings||[]).map(f=>"["+m.module+"] "+f.title+": "+f.detail)).join("\\n");
  let h="";
  if(d.exposure){const e=d.exposure;
    h+='<div class="pan"><div class="h">EXPOSURE<span class="r">grade '+e.grade+'</span></div><div class="b">'+
      '<div class="score"><div class="grade g-'+e.grade+'">'+e.grade+'</div><div class="sc">'+e.score+'/100</div>'+
      '<div class="bar"><span style="width:'+e.score+'%"></span></div></div>'+
      ((e.factors||[]).length?'<div class="fac">'+e.factors.map(esc).join(' · ')+'</div>':'')+
      ((e.recommendations||[]).length?'<ul class="recs">'+e.recommendations.map(r=>'<li>'+esc(r)+'</li>').join('')+'</ul>':'')+
      '</div></div>';}
  const V=verifyItems(d);
  if(V.length){h+='<div class="pan"><div class="h">VERIFY — is it him?<span class="r">'+V.length+' links</span></div><div class="b">';
    for(const v of V)h+='<div class="vr">'+(v.image?'<img src="'+esc(v.image)+'" referrerpolicy="no-referrer" onerror="this.remove()">':'')+
      '<div class="vm"><span class="plat">'+esc(v.label)+'</span><a href="'+esc(v.url)+'" target="_blank" rel="noreferrer">'+esc(v.url)+'</a>'+(v.bio?'<p>'+esc(v.bio)+'</p>':'')+(v.image?ris(v.image):'')+'</div>'+
      '<div class="vb"><button class="vy">YES</button><button class="vk">MAYBE</button><button class="vn">NO</button></div></div>';
    h+='</div></div>';}
  if(d.graph&&d.graph.nodes.length)h+='<div class="pan"><div class="h">ENTITY NETWORK<span class="r">'+d.graph.nodes.length+' / '+d.graph.links.length+'</span></div><canvas id="graph" width="400" height="260"></canvas><div class="ghint">drag to arrange · click a node to load it into the scan bar</div></div>';
  h+='<div class="pan"><div class="h">BRIEFING<span class="r">'+(d.ai_used?"CLAUDE":"RAW")+'</span></div><div class="b summary">'+esc(d.summary)+'</div></div>';
  const fp=d.footprint;
  if(fp&&!fp.first_scan&&((fp.added||[]).length||(fp.removed||[]).length)){
    h+='<div class="pan"><div class="h">CHANGES SINCE LAST SCAN<span class="r">'+fp.total+' total</span></div><div class="b">';
    for(const a of (fp.added||[]))h+='<div class="dl add">+ '+esc(a)+'</div>';
    for(const r of (fp.removed||[]))h+='<div class="dl rem">− '+esc(r)+'</div>';
    h+='</div></div>';}
  if(d.timeline&&d.timeline.length){h+='<div class="pan"><div class="h">TIMELINE<span class="r">'+d.timeline.length+'</span></div><div class="b">';
    for(const t of d.timeline)h+='<div class="tl"><span class="td">'+esc(t.date)+'</span><span class="tw">'+esc(t.what)+'</span><span class="ts">'+esc(t.source)+'</span></div>';
    h+='</div></div>';}
  if(d.removal&&((d.removal.accounts||[]).length||(d.removal.brokers||[]).length)){
    h+='<div class="pan"><div class="h">REMOVE ME<span class="r">opt-out</span></div><div class="b">';
    if((d.removal.accounts||[]).length){h+='<div class="rl-h">Accounts found — deactivate:</div>';
      for(const a of d.removal.accounts)h+='<div class="rl"><b>'+esc(a.platform)+'</b> '+linkify(a.url)+'</div>';}
    h+='<div class="rl-h">Data brokers — opt out:</div>';
    for(const b of d.removal.brokers)h+='<div class="rl"><b>'+esc(b.name)+'</b> <a href="'+esc(b.url)+'" target="_blank" rel="noreferrer">'+esc(b.url)+'</a></div>';
    h+='</div></div>';}
  h+='<div class="pan"><div class="h">FINDINGS<button id="dlrep" class="r rbtn">⇩ REPORT</button></div><div class="b">';
  for(const m of d.results)for(const f of (m.findings||[]))if(!m.skipped)h+='<div class="f"><b>'+esc(m.module)+'</b> · '+esc(f.title)+': '+esc(f.detail)+'</div>';
  h+='</div></div>';
  $("out").innerHTML=h;
  window.LAST=d;
  const db=$("dlrep");if(db)db.onclick=()=>downloadReport(d);
  if(d.graph&&d.graph.nodes.length)drawGraph(d.graph);
}
function linkify(s){const m=String(s).match(/https?:\\/\\/\\S+/);return m?'<a href="'+esc(m[0])+'" target="_blank" rel="noreferrer">'+esc(m[0])+'</a> '+esc(s.replace(m[0],'')):esc(s);}
function downloadReport(d){
  let b='<h1>CYPHER report — '+esc(d.target)+'</h1><p class="mt">'+esc(d.target_type)+' · '+(d.ai_used?'Claude':'raw')+'</p>';
  if(d.exposure)b+='<h2>Exposure</h2><p>Grade <b>'+d.exposure.grade+'</b> · '+d.exposure.score+'/100</p><p>'+(d.exposure.factors||[]).map(esc).join(' · ')+'</p>';
  b+='<h2>Briefing</h2><pre>'+esc(d.summary)+'</pre>';
  if(d.timeline&&d.timeline.length){b+='<h2>Timeline</h2><ul>';for(const t of d.timeline)b+='<li>'+esc(t.date)+' — '+esc(t.what)+' ('+esc(t.source)+')</li>';b+='</ul>';}
  b+='<h2>Findings</h2><ul>';
  for(const m of d.results)for(const f of (m.findings||[]))if(!m.skipped)b+='<li><b>'+esc(m.module)+'</b> · '+esc(f.title)+': '+esc(f.detail)+'</li>';
  b+='</ul>';
  if(d.removal){b+='<h2>Remove me</h2><ul>';for(const a of (d.removal.accounts||[]))b+='<li>'+esc(a.platform)+': '+esc(a.url)+'</li>';for(const x of (d.removal.brokers||[]))b+='<li>'+esc(x.name)+': '+esc(x.url)+'</li>';b+='</ul>';}
  const doc='<!doctype html><meta charset="utf-8"><title>CYPHER '+esc(d.target)+'</title><style>body{background:#0a0510;color:#f4eef2;font:14px/1.6 system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px}h1,h2{color:#ff5db1;border-bottom:1px solid #7a2f53;padding-bottom:6px}a{color:#ff9ed6}pre{white-space:pre-wrap;background:#050505;border:1px solid #7a2f53;padding:12px;border-radius:8px}.mt{color:#b89aab}li{margin:3px 0}</style>'+b;
  const blob=new Blob([doc],{type:"text/html"}),u=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=u;a.download="cypher-"+d.target.replace(/[^a-z0-9]+/gi,"_")+".html";a.click();URL.revokeObjectURL(u);
}
$("out").addEventListener("click",e=>{const c=e.target.closest(".vr");if(!c)return;
  const cl=e.target.classList;
  if(cl.contains("vy")||cl.contains("vk")||cl.contains("vn")){
    c.classList.remove("v-yes","v-maybe","v-no");
    c.classList.add(cl.contains("vy")?"v-yes":cl.contains("vk")?"v-maybe":"v-no");}});

let _raf=null;
function drawGraph(g){const cv=$("graph");if(!cv)return;const ctx=cv.getContext("2d"),W=cv.width,H=cv.height;
  const col={domain:"#7bb8ff",ip:"#5ef2a8",email:"#ffb454",url:"#ff9ed6",username:"#c79bff",phone:"#5ef2a8",crypto:"#ffd36b",name:"#c79bff",image:"#ff9ed6",module:"#75566b"};
  const root=g.nodes[0].id;
  const N=g.nodes.map(n=>({...n,x:W/2+(Math.random()-.5)*160,y:H/2+(Math.random()-.5)*160,vx:0,vy:0,fx:null,fy:null}));
  const ix={};N.forEach((n,i)=>ix[n.id]=i);const L=g.links.filter(l=>l.source in ix&&l.target in ix);
  const rad=n=>n.id===root?8:(n.group==="module"?3:5);
  let hover=-1,drag=-1,moved=false;
  const at=e=>{const b=cv.getBoundingClientRect();return {x:(e.clientX-b.left)*W/b.width,y:(e.clientY-b.top)*H/b.height};};
  const pick=p=>{let best=-1,bd=1e9;for(let i=0;i<N.length;i++){const dx=N[i].x-p.x,dy=N[i].y-p.y,d=dx*dx+dy*dy,rr=(rad(N[i])+6)*(rad(N[i])+6);if(d<rr&&d<bd){bd=d;best=i;}}return best;};
  cv.onmousedown=e=>{const i=pick(at(e));if(i>=0){drag=i;moved=false;}};
  cv.onmousemove=e=>{const p=at(e);if(drag>=0){N[drag].fx=p.x;N[drag].fy=p.y;moved=true;cv.style.cursor="grabbing";return;}hover=pick(p);cv.style.cursor=hover>=0?"pointer":"default";};
  cv.onmouseup=()=>{if(drag>=0){const n=N[drag];if(!moved&&n.group!=="module"&&n.id!==root){$("target").value=n.id;$("target").focus();$("side").textContent="↑ '"+n.id+"' loaded — pick a category and RUN";}n.fx=null;n.fy=null;drag=-1;}};
  cv.onmouseleave=()=>{hover=-1;if(drag>=0){N[drag].fx=null;N[drag].fy=null;drag=-1;}cv.style.cursor="default";};
  if(_raf)cancelAnimationFrame(_raf);
  (function step(){
    for(let i=0;i<N.length;i++)for(let j=i+1;j<N.length;j++){const a=N[i],b=N[j];
      let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1,f=900/(d*d);dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const l of L){const a=N[ix[l.source]],b=N[ix[l.target]];let dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1,f=(d-70)*.02;
      dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;}
    for(const n of N){if(n.fx!=null){n.x=n.fx;n.y=n.fy;n.vx=0;n.vy=0;}
      else{n.vx+=(W/2-n.x)*.003;n.vy+=(H/2-n.y)*.003;n.vx*=.85;n.vy*=.85;n.x+=n.vx;n.y+=n.vy;}}
    const hid=hover>=0?N[hover].id:null;
    ctx.clearRect(0,0,W,H);
    for(const l of L){const a=N[ix[l.source]],b=N[ix[l.target]],on=hid&&(l.source===hid||l.target===hid);
      ctx.strokeStyle=on?"#ff5db1":"#3a2233";ctx.lineWidth=on?1.6:1;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
    ctx.font="9px monospace";
    for(let k=0;k<N.length;k++){const n=N[k],r=rad(n)*(k===hover?1.6:1);ctx.fillStyle=col[n.group]||"#f0dced";
      ctx.beginPath();ctx.arc(n.x,n.y,r,0,7);ctx.fill();ctx.fillStyle=k===hover?"#ffd0ea":"#b088a0";ctx.fillText((n.label||"").slice(0,18),n.x+r+2,n.y+3);}
    _raf=requestAnimationFrame(step);
  })();
}
</script>
</body></html>"""
