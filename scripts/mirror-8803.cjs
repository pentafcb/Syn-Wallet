// Syn Wallet :8803 mirror (audit NEW LOW 11, 2026-11-19).
// A same-box HTTPS reverse proxy: :8803 serves exactly what the main
// service on :8801 serves, on a second port. It exists because the
// owner's phone had a stuck cached copy of the :8801 origin; :8803 is
// a fresh origin pointing at the same live build. It holds no state
// and proxies verbatim (TLS cert shared with the main service).
// Installed as a persistent systemd unit (syn-wallet-mirror.service,
// see this repo) — before the audit pass it was an unversioned
// transient unit in /root that a reboot would have lost.
const https = require("https");
const fs = require("fs");
const opts = { cert: fs.readFileSync("/root/syn-wallet/data/tls/cert.pem"), key: fs.readFileSync("/root/syn-wallet/data/tls/key.pem") };
https.createServer(opts, (req, res) => {
  const up = https.request({ host: "127.0.0.1", port: 8801, path: req.url, method: req.method, headers: { ...req.headers, host: "127.0.0.1:8801" }, rejectUnauthorized: false }, (ur) => { res.writeHead(ur.statusCode, ur.headers); ur.pipe(res); });
  up.on("error", () => { res.writeHead(502); res.end("upstream error"); });
  req.pipe(up);
}).listen(8803, () => console.log("mirror on 8803"));
