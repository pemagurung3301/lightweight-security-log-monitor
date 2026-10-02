"""
dashboard.py
────────────
A small web GUI for the monitor – built only with the Python standard
library (http.server), so the project keeps its zero-extra-dependency claim.

Start it from the monitor with:

    python3 monitor.py --os linux --gui

…or on its own for a screenshot/demo:

    python3 dashboard.py

Open http://localhost:8080 in a browser.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_HOST = "0.0.0.0"   # 0.0.0.0 so other machines on the LAN can see the demo
DEFAULT_PORT = 8080

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lightweight Security Log Monitor</title>
<style>
  :root { --bg:#0b1020; --card:#141b33; --line:#26304f; --tx:#e8ecff;
          --dim:#8f9bc7; --red:#ff5470; --amber:#ffb020; --grn:#3ddc97; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--tx);
         font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif; }
  header { padding:18px 26px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
  h1 { font-size:18px; margin:0; letter-spacing:.3px; }
  .pill { font-size:11px; padding:3px 10px; border-radius:999px;
          border:1px solid var(--line); color:var(--dim); }
  .pill.live { color:var(--grn); border-color:var(--grn); }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--grn);
         display:inline-block; margin-right:6px; animation:pulse 1.6s infinite; }
  @keyframes pulse { 50% { opacity:.25 } }
  main { padding:22px 26px; display:grid; gap:18px;
         grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); }
  .card { background:var(--card); border:1px solid var(--line);
          border-radius:12px; padding:16px 18px; }
  .card h2 { margin:0 0 8px; font-size:11px; text-transform:uppercase;
             letter-spacing:1.2px; color:var(--dim); font-weight:600; }
  .big { font-size:30px; font-weight:650; }
  .sub { color:var(--dim); font-size:12px; }
  .wide { grid-column:1/-1; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line);
          font-size:13px; vertical-align:top; }
  th { color:var(--dim); font-weight:600; font-size:11px; text-transform:uppercase;
       letter-spacing:.8px; }
  .bar { height:6px; background:#20294a; border-radius:4px; overflow:hidden;
         min-width:110px; }
  .bar > i { display:block; height:100%; background:var(--amber); }
  .bar.hot > i { background:var(--red); }
  .tag { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px;
         background:#1b2444; padding:2px 7px; border-radius:6px; }
  .alert { border-left:3px solid var(--red); background:#1a1330;
           padding:10px 14px; border-radius:8px; margin-bottom:10px;
           white-space:pre-wrap; font-family:ui-monospace,Menlo,Consolas,monospace;
           font-size:12px; }
  .ok { color:var(--grn) } .warn { color:var(--amber) } .bad { color:var(--red) }
  ul.feed { list-style:none; margin:0; padding:0; max-height:260px; overflow:auto; }
  ul.feed li { padding:6px 0; border-bottom:1px solid var(--line);
               font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; }
  .empty { color:var(--dim); font-style:italic; }
  footer { padding:14px 26px; color:var(--dim); font-size:12px;
           border-top:1px solid var(--line); }
</style>
</head>
<body>
<header>
  <h1>🛡️ Lightweight Security Log Monitor</h1>
  <span class="pill live"><span class="dot"></span><span id="status">starting…</span></span>
  <span class="pill" id="source">–</span>
  <span class="pill" id="rule">–</span>
  <span class="pill" id="alerts-to">–</span>
</header>

<main>
  <div class="card"><h2>Failed logins seen</h2>
    <div class="big" id="c-fail">0</div><div class="sub">since the monitor started</div></div>
  <div class="card"><h2>Alerts fired</h2>
    <div class="big" id="c-alert">0</div><div class="sub" id="c-alertsub">–</div></div>
  <div class="card"><h2>Distinct source IPs</h2>
    <div class="big" id="c-ips">0</div><div class="sub">active in the current window</div></div>
  <div class="card"><h2>Uptime</h2>
    <div class="big" id="c-up">0s</div><div class="sub" id="c-start">–</div></div>

  <div class="card wide"><h2>Attackers in the current window</h2>
    <table><thead><tr><th>Source IP</th><th>Failures</th><th></th>
      <th>Usernames tried</th><th>Last seen</th></tr></thead>
      <tbody id="attackers"><tr><td colspan="5" class="empty">Waiting for events…</td></tr></tbody>
    </table></div>

  <div class="card"><h2>Alert feed</h2><div id="alertfeed">
    <div class="empty">No alerts yet.</div></div></div>

  <div class="card"><h2>Live events</h2><ul class="feed" id="events">
    <li class="empty">Waiting for events…</li></ul></div>
</main>

<footer>Lightweight Security Log Monitor · polls the monitor every 2&nbsp;s ·
  built with the Python standard library only</footer>

<script>
const $ = id => document.getElementById(id);
function esc(s){ return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

async function tick() {
  let s;
  try {
    const r = await fetch('api/state', {cache:'no-store'});
    s = await r.json();
  } catch (e) { $('status').textContent = 'disconnected'; return; }

  $('status').textContent   = s.running ? 'monitoring' : 'stopped';
  $('source').textContent   = 'source: ' + s.source;
  $('rule').textContent     = 'rule: ' + s.threshold.max_failures +
                              ' failures / ' + s.threshold.window_secs + 's';
  $('alerts-to').textContent = 'alerts via: ' + s.alert_channels;

  $('c-fail').textContent  = s.counters.total_failures;
  $('c-alert').textContent = s.counters.total_alerts;
  $('c-alertsub').textContent = s.counters.last_alert || 'nothing yet';
  $('c-ips').textContent   = s.threshold.active_ips.length;
  $('c-up').textContent    = s.uptime;
  $('c-start').textContent = 'started ' + s.started_at;

  const rows = s.threshold.active_ips.map(a => {
    const pct = Math.min(100, Math.round(a.failure_count / s.threshold.max_failures * 100));
    const hot = a.breached ? ' hot' : '';
    return '<tr><td><span class="tag">' + esc(a.source_ip) + '</span></td>' +
           '<td>' + a.failure_count + '/' + s.threshold.max_failures +
           (a.breached ? ' <span class="bad">⚠</span>' : '') + '</td>' +
           '<td><div class="bar' + hot + '"><i style="width:' + pct + '%"></i></div></td>' +
           '<td>' + esc(a.usernames.join(', ')) + '</td>' +
           '<td class="sub">' + esc(a.last_seen) + '</td></tr>';
  });
  $('attackers').innerHTML = rows.length ? rows.join('')
      : '<tr><td colspan="5" class="empty">No failures in the current window.</td></tr>';

  $('alertfeed').innerHTML = s.alerts.length
      ? s.alerts.map(a => '<div class="alert">' + esc(a.message) + '</div>').join('')
      : '<div class="empty">No alerts yet.</div>';

  $('events').innerHTML = s.recent_events.length
      ? s.recent_events.map(e => '<li><span class="sub">' + esc(e.at) + '</span> ' +
            '<span class="tag">' + esc(e.source_ip) + '</span> user=' +
            esc(e.username) + ' <span class="sub">(' + esc(e.os) + ')</span></li>').join('')
      : '<li class="empty">Waiting for events…</li>';
}
tick(); setInterval(tick, 2000);
</script>
</body></html>
"""


class Dashboard:
    """Serves the web GUI in a background thread."""

    def __init__(self, state_provider, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.state_provider = state_provider
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None

    # ── public API ───────────────────────────────────────────
    def start(self) -> int:
        """Start the server. Returns the port actually in use."""
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):                      # noqa: N802 (http.server API)
                if self.path in ("/", "/index.html"):
                    self._send(200, PAGE, "text/html; charset=utf-8")
                elif self.path.startswith("/api/state"):
                    try:
                        payload = json.dumps(dashboard.state_provider(),
                                             ensure_ascii=False, default=str)
                    except Exception as e:       # never take the GUI down
                        payload = json.dumps({"error": str(e)})
                    self._send(200, payload, "application/json; charset=utf-8")
                else:
                    self._send(404, "not found", "text/plain")

            def _send(self, code, body, ctype):
                data = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass                              # keep the terminal clean

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True, name="dashboard")
        self._thread.start()
        return self.port

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


if __name__ == "__main__":
    # Stand-alone preview with fake data, so you can look at the GUI
    # before any real log data exists.
    import time
    fake = {
        "running": True, "source": "preview (no log attached)",
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"), "uptime": "0s",
        "alert_channels": "preview",
        "counters": {"total_failures": 0, "total_alerts": 0, "last_alert": None},
        "threshold": {"max_failures": 5, "window_secs": 180, "cooldown_secs": 300,
                      "total_failures": 0, "total_alerts": 0, "active_ips": []},
        "alerts": [], "recent_events": [],
    }
    d = Dashboard(lambda: fake)
    port = d.start()
    print(f"[*] Preview dashboard on http://localhost:{port}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Preview stopped.")
