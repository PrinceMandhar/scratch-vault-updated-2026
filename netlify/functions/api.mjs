import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import SEED from "./seed.mjs";

const SECRET = process.env.SESSION_SECRET || "";
const PASS = process.env.ADMIN_PASSWORD || "";
const VPASS = process.env.TEAM_PASSWORD || process.env.VIEWER_PASSWORD || "";
const PER_CARD = 250000;
const sha = x => crypto.createHash("sha256").update(String(x)).digest();
const hmac = x => crypto.createHmac("sha256", SECRET).update(x).digest("hex");
const SEEDH = sha(JSON.stringify(SEED)).toString("hex").slice(0, 16);
const eq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const mkTok = role => { const e = Date.now() + 4 * 3600e3; return e + "." + role + "." + hmac(role + e); };
const okTok = (t, role) => { const [e, r, s] = String(t || "").split("."); return !!SECRET && !!e && r === role && !!s && eq(s, hmac(role + e)) && +e > Date.now(); };
const json = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const norm = s => String(s || "").trim().replace(/\s+/g, " ").toLowerCase();
const clean = s => String(s ?? "").replace(/[\u0000-\u001f<>&"'`\\]/g, "").replace(/\s+/g, " ").trim().slice(0, 80);
const now = () => new Date().toISOString();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const store = () => getStore("scratch");

// ---- brute-force guard (login + link gate) ----
const gs = () => getStore("guard");
async function blocked(k, limit, win) { const r = await gs().get(k, { type: "json" }); return !!r && r.n >= limit && Date.now() - r.t < win; }
async function strike(k, win) { let r = await gs().get(k, { type: "json" }) || { n: 0, t: 0 }; if (Date.now() - r.t > win) r.n = 0; r.n++; r.t = Date.now(); await gs().setJSON(k, r); }
const clear = k => gs().setJSON(k, { n: 0, t: 0 });

const mkDb = () => ({ seedHash: SEEDH, cards: SEED.map(([no, code, cat, wt]) => ({ no, code, cat, wt, status: "Available", party: "", ticket: "", revealedAt: "", claim: "" })), tickets: [], log: [] });
async function load() {
  const r = await store().getWithMetadata("db", { type: "json" });
  const x = r && r.data;
  if (x && (x.seedHash === SEEDH || x.tickets.length || x.cards.some(c => c.status !== "Available"))) return { d: x, etag: r.etag };
  return { d: mkDb(), etag: r ? r.etag : null, fresh: true };
}
const view = (d, t) => t.cards.map(no => {
  const c = d.cards.find(x => x.no === no), r = c.status === "Revealed";
  return { no, revealed: r, ...(r ? { cat: c.cat, wt: c.wt, code: c.code, at: c.revealedAt } : {}) };
});
const addLog = (d, who, act) => { d.log.push({ at: now(), who, act }); if (d.log.length > 3000) d.log.splice(0, d.log.length - 3000); };

export default async (req) => {
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  const o = req.headers.get("origin");
  try { if (o && new URL(o).host !== new URL(req.url).host) return json({ error: "Forbidden" }, 403); } catch { return json({ error: "Forbidden" }, 403); }
  const raw = await req.text();
  if (raw.length > 8000) return json({ error: "Too large" }, 413);
  let p; try { p = JSON.parse(raw); } catch { return json({ error: "Bad request" }, 400); }
  if (!p || typeof p !== "object") return json({ error: "Bad request" }, 400);
  const a = p.a, ip = hmac(req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for") || "?");

  if (a === "login") {
    if (!PASS || !SECRET || SECRET.length < 16) return json({ error: "Server setup incomplete: ADMIN_PASSWORD / SESSION_SECRET set karein." }, 503);
    const k = "L" + ip;
    if (await blocked(k, 5, 15 * 60e3)) return json({ error: "Bahut zyada galat attempts. 15 minute baad try karein." }, 429);
    const view = p.role === "view";
    if (view && !VPASS) return json({ error: "Team password set nahi hai (TEAM_PASSWORD)." }, 503);
    if (typeof p.password === "string" && eq(p.password, view ? VPASS : PASS)) { await clear(k); return json({ tok: mkTok(view ? "view" : "adm") }); }
    await strike(k, 15 * 60e3); await sleep(400); return json({ error: "Galat password" }, 401);
  }
  if (a === "open" || a === "scratch") {
    const gk = "G" + ip + String(p.t).slice(0, 24);
    if (await blocked(gk, 8, 10 * 60e3)) return json({ error: "Bahut zyada attempts. Thodi der baad try karein." }, 429);
    p._gk = gk;
  } else if (!okTok(p.tok, a === "vstate" ? "view" : "adm")) return json({ error: "Session expire. Dobara login karein." }, 401);

  for (let i = 0; i < 12; i++) {
    const { d, etag, fresh } = await load();
    if (fresh) d.__dirty = true;
    const res = await run(a, p, d);
    if (!d.__dirty) return res;
    delete d.__dirty;
    const w = await store().setJSON("db", d, etag ? { onlyIfMatch: etag } : { onlyIfNew: true });
    if (w && w.modified === false) { await sleep(20 + Math.random() * 80); continue; }
    return res;
  }
  return json({ error: "Server busy, dobara try karein." }, 503);
};

function gate(d, p) {
  const t = /^[a-f0-9]{24}$/.test(String(p.t)) && d.tickets.find(x => x.token === p.t);
  const v = Number(String(p.value).replace(/,/g, ""));
  if (!t || t.status !== "Active" || norm(t.party) !== norm(p.party) || t.value !== v) return [null, "Details match nahi hui ya link active nahi hai."];
  return [t, null];
}

async function run(a, p, d) {
  if (a === "open" || a === "scratch") {
    const [t, e] = gate(d, p);
    if (e) { await strike(p._gk, 10 * 60e3); return json({ error: e }, 403); }
    if (a === "open") return json({ party: t.party, cards: view(d, t) });
    if (!/^SC-\d{4}$/.test(String(p.no)) || !t.cards.includes(p.no)) return json({ error: "Card is ticket ka nahi hai." }, 403);
    const c = d.cards.find(x => x.no === p.no);
    if (c.status !== "Revealed") {
      c.status = "Revealed"; c.revealedAt = now(); c.claim = "Pending";
      addLog(d, t.party, "Scratched " + c.no + " (" + c.code + ") " + c.cat + " " + c.wt); d.__dirty = true;
    }
    return json({ no: c.no, cat: c.cat, wt: c.wt, code: c.code, at: c.revealedAt });
  }
  if (a === "vstate") return json({
    cards: d.cards.map(c => ({ no: c.no, cat: c.cat, wt: c.wt, status: c.status, party: c.party, ticket: c.ticket, revealedAt: c.revealedAt, claim: c.claim, code: c.status === "Revealed" ? c.code : c.code.slice(0, 2) + "******" })),
    tickets: d.tickets.map(({ token, ...t }) => t), log: d.log.slice(-300).reverse()
  });
  if (a === "reset") {
    if (p.confirm !== "RESET ALL" || typeof p.password !== "string" || !eq(p.password, PASS)) return json({ error: "Confirmation ya password galat." }, 403);
    Object.assign(d, mkDb()); addLog(d, "admin", "FULL RESET"); d.__dirty = true; return json({ ok: 1 });
  }
  if (a === "state") return json({ cards: d.cards, tickets: d.tickets, log: d.log.slice(-300).reverse() });
  if (a === "backup") return json({ exported: now(), ...d });
  if (a === "create") {
    const party = clean(p.party), value = Math.round(Number(p.value));
    if (!party || !(value > 0) || value > 1e10) return json({ error: "Valid party name aur order value daalein." }, 400);
    const qty = p.qty ? Number(p.qty) : Math.floor(value / PER_CARD);
    if (!Number.isInteger(qty) || qty < 1 || qty > 100) return json({ error: "Order value 2.5 lakh se kam hai (ya qty galat). Qty manually 1-100 dein." }, 400);
    const free = d.cards.filter(c => c.status === "Available");
    if (free.length < qty) return json({ error: "Sirf " + free.length + " cards bache hain." }, 400);
    for (let i = free.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [free[i], free[j]] = [free[j], free[i]]; }
    const pick = free.slice(0, qty);
    const t = { id: "TK-" + String(d.tickets.length + 1).padStart(3, "0"), token: crypto.randomBytes(12).toString("hex"), party, value, cards: pick.map(c => c.no), status: "Active", created: now() };
    pick.forEach(c => { c.status = "Assigned"; c.party = party; c.ticket = t.id; });
    d.tickets.push(t); addLog(d, "admin", "Ticket " + t.id + " for " + party + " (" + qty + " cards)"); d.__dirty = true;
    return json({ ticket: t });
  }
  if (a === "revoke") {
    const t = d.tickets.find(x => x.id === p.id); if (!t) return json({ error: "Not found" }, 404);
    t.status = t.status === "Active" ? "Revoked" : "Active"; addLog(d, "admin", t.id + " " + t.status); d.__dirty = true; return json({ ok: 1 });
  }
  if (a === "claim") {
    const c = d.cards.find(x => x.no === p.no);
    if (!c || c.status !== "Revealed" || !["Pending", "Approved", "Fulfilled", "Rejected"].includes(p.claim)) return json({ error: "Invalid" }, 400);
    c.claim = p.claim; addLog(d, "admin", "Claim " + c.no + " -> " + p.claim); d.__dirty = true; return json({ ok: 1 });
  }
  return json({ error: "Unknown action" }, 400);
}
export const config = { path: "/api" };
