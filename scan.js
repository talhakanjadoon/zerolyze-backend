const https = require("https");
const http = require("http");
const tls = require("tls");
const { URL } = require("url");

function fetchHeaders(targetUrl) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(targetUrl);
      const lib = parsed.protocol === "https:" ? https : http;
      const req = lib.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
          path: parsed.pathname || "/",
          method: "HEAD",
          timeout: 8000,
          headers: { "User-Agent": "Zerolyze-Scanner/1.0" },
        },
        (res) => resolve({ status: res.statusCode, headers: res.headers, location: res.headers["location"] || null })
      );
      req.on("error", () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.end();
    } catch { resolve(null); }
  });
}

function checkSSL(hostname) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect(
        { host: hostname, port: 443, servername: hostname, timeout: 8000 },
        () => {
          const cert = socket.getPeerCertificate(true);
          const valid = socket.authorized;
          const exp = cert?.valid_to ? new Date(cert.valid_to) : null;
          const daysLeft = exp ? Math.floor((exp - Date.now()) / 86400000) : null;
          socket.destroy();
          resolve({ hasSSL: true, valid, expiresAt: exp?.toDateString(), daysLeft });
        }
      );
      socket.on("error", () => resolve({ hasSSL: false, valid: false, expiresAt: null, daysLeft: null }));
      socket.on("timeout", () => { socket.destroy(); resolve({ hasSSL: false, valid: false, expiresAt: null, daysLeft: null }); });
    } catch { resolve({ hasSSL: false, valid: false, expiresAt: null, daysLeft: null }); }
  });
}

async function checkHttpsRedirect(hostname) {
  const res = await fetchHeaders(`http://${hostname}/`);
  if (!res) return false;
  if ([301, 302, 307, 308].includes(res.status) && res.location) return res.location.startsWith("https://");
  return false;
}

async function checkExposedFiles(baseUrl) {
  const paths = ["/.env", "/.git/HEAD", "/config.php", "/wp-config.php", "/backup.zip", "/.htpasswd"];
  const exposed = [];
  const parsed = new URL(baseUrl);
  const lib = parsed.protocol === "https:" ? https : http;
  await Promise.all(paths.map(async (p) => {
    try {
      const code = await new Promise((resolve) => {
        const req = lib.request(
          { hostname: parsed.hostname, path: p, method: "GET", timeout: 5000, headers: { "User-Agent": "Zerolyze-Scanner/1.0" } },
          (res) => resolve(res.statusCode)
        );
        req.on("error", () => resolve(null));
        req.on("timeout", () => { req.destroy(); resolve(null); });
        req.end();
      });
      if (code === 200) exposed.push(p);
    } catch {}
  }));
  return exposed;
}

function analyzeHeaders(headers) {
  const h = headers || {};
  return {
    csp: !!h["content-security-policy"],
    xframe: !!h["x-frame-options"],
    xContentType: h["x-content-type-options"] === "nosniff",
    hsts: !!h["strict-transport-security"],
    referrer: !!h["referrer-policy"],
    permissions: !!h["permissions-policy"],
    server: h["server"] || null,
    poweredBy: h["x-powered-by"] || null,
  };
}

function scoreit(checks) {
  const w = { ssl:25, sslValid:5, httpsRedirect:10, hsts:10, csp:15, xframe:8, xContentType:7, referrer:5, permissions:5, noServerLeak:5, noExposedFiles:5 };
  return Math.min(100, Object.entries(w).reduce((s, [k, v]) => s + (checks[k] ? v : 0), 0));
}

function buildFindings(checks, sslInfo, headerInfo, exposedFiles) {
  const f = [];
  if (!checks.ssl) f.push({ severity:"critical", title:"No SSL certificate", detail:"All data transmitted in plain text — passwords, forms, everything is visible on the network.", fix:"Install free SSL via Let's Encrypt at certbot.eff.org" });
  else if (!checks.sslValid) f.push({ severity:"critical", title:"SSL certificate invalid or expired", detail:`Expires: ${sslInfo.expiresAt || "unknown"}. Browsers show scary warnings to visitors.`, fix:"Renew SSL certificate through your hosting provider immediately." });
  else if (sslInfo.daysLeft !== null && sslInfo.daysLeft < 30) f.push({ severity:"high", title:`SSL expires in ${sslInfo.daysLeft} days`, detail:"After expiry visitors see a security warning and most will leave your site.", fix:"Renew your certificate now — don't wait." });
  if (!checks.httpsRedirect) f.push({ severity:"high", title:"HTTP not redirecting to HTTPS", detail:"Users who type your URL without https:// land on an insecure page.", fix:"Add a 301 redirect in .htaccess or nginx config." });
  if (!checks.hsts) f.push({ severity:"high", title:"HSTS header missing", detail:"Attackers can downgrade HTTPS connections to HTTP and intercept data.", fix:"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains" });
  if (!checks.csp) f.push({ severity:"high", title:"Content-Security-Policy missing", detail:"No defense against XSS attacks — attackers can inject malicious scripts.", fix:"Start with: Content-Security-Policy: default-src 'self'" });
  if (!checks.xframe) f.push({ severity:"medium", title:"X-Frame-Options missing", detail:"Your site can be embedded in malicious iframes for clickjacking attacks.", fix:"Add: X-Frame-Options: DENY" });
  if (!checks.xContentType) f.push({ severity:"medium", title:"X-Content-Type-Options missing", detail:"Browsers may misread file types enabling MIME-type attacks.", fix:"Add: X-Content-Type-Options: nosniff" });
  if (!checks.referrer) f.push({ severity:"low", title:"Referrer-Policy not set", detail:"Your full URL leaks to every third-party service your site loads.", fix:"Add: Referrer-Policy: strict-origin-when-cross-origin" });
  if (!checks.noServerLeak) f.push({ severity:"low", title:`Server info exposed: ${headerInfo.server || headerInfo.poweredBy}`, detail:"Advertising server software helps attackers find known vulnerabilities.", fix:"Remove or mask Server and X-Powered-By headers." });
  if (exposedFiles.length > 0) f.push({ severity:"critical", title:`${exposedFiles.length} sensitive file(s) exposed`, detail:`Found publicly accessible: ${exposedFiles.join(", ")}`, fix:"Block these paths immediately in your web server config." });
  return f;
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: "URL is required." });

  let parsed;
  try { parsed = new URL(url.startsWith("http") ? url : "https://" + url); }
  catch { return res.status(400).json({ error: "Invalid URL format." }); }

  const hostname = parsed.hostname;
  const baseUrl = `${parsed.protocol}//${hostname}`;

  try {
    const [sslInfo, httpsRedirect, headersRes, exposedFiles] = await Promise.all([
      checkSSL(hostname),
      checkHttpsRedirect(hostname),
      fetchHeaders(baseUrl),
      checkExposedFiles(baseUrl),
    ]);

    const headerInfo = analyzeHeaders(headersRes?.headers);
    const checks = {
      ssl: sslInfo.hasSSL,
      sslValid: sslInfo.valid,
      httpsRedirect,
      hsts: headerInfo.hsts,
      csp: headerInfo.csp,
      xframe: headerInfo.xframe,
      xContentType: headerInfo.xContentType,
      referrer: headerInfo.referrer,
      permissions: headerInfo.permissions,
      noServerLeak: !headerInfo.server && !headerInfo.poweredBy,
      noExposedFiles: exposedFiles.length === 0,
    };

    const score = scoreit(checks);
    const grade = score>=90?"A":score>=75?"B":score>=60?"C":score>=45?"D":"F";

    return res.status(200).json({
      domain: hostname,
      scannedAt: new Date().toISOString(),
      score, grade,
      ssl: sslInfo,
      checks, headerInfo, exposedFiles,
      findings: buildFindings(checks, sslInfo, headerInfo, exposedFiles),
      passCount: Object.values(checks).filter(Boolean).length,
      failCount: Object.values(checks).filter(v => !v).length,
    });
  } catch {
    return res.status(500).json({ error: "Scan failed. Please try again." });
  }
};
