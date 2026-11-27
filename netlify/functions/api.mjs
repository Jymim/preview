import { getStore } from "@netlify/blobs";
import { scryptSync, randomBytes, timingSafeEqual, createHmac } from "node:crypto";

export const config = { path: "/api/*" };

const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json" } });
const secret = () => Netlify.env.get("JWT_SECRET");
const mac = (b) => createHmac("sha256", secret()).update(b).digest("base64url");
const sign = (p) => {
  const b = Buffer.from(JSON.stringify({ ...p, exp: Date.now() + 7 * 864e5 })).toString("base64url");
  return b + "." + mac(b);
};
const verify = (t) => {
  const [b, s] = (t || "").split(".");
  if (!b || !s || s.length !== mac(b).length || !timingSafeEqual(Buffer.from(s), Buffer.from(mac(b)))) return null;
  const p = JSON.parse(Buffer.from(b, "base64url").toString());
  return p.exp > Date.now() ? p : null;
};
const hash = (pw, salt = randomBytes(16).toString("hex")) => salt + ":" + scryptSync(pw, salt, 32).toString("hex");
const same = (pw, h) => {
  const a = Buffer.from(hash(pw, h.split(":")[0])), b = Buffer.from(h);
  return a.length === b.length && timingSafeEqual(a, b);
};
const clean = (s, n = 500) => String(s ?? "").trim().slice(0, n);
const getAll = async (store, prefix) => {
  const { blobs } = await store.list({ prefix });
  return (await Promise.all(blobs.map((b) => store.get(b.key, { type: "json" })))).filter(Boolean);
};

export default async (req) => {
  if (!secret()) return json({ error: "Server not configured: set JWT_SECRET" }, 500);
  const store = getStore("logbook");
  const path = new URL(req.url).pathname.replace(/^\/api\/?/, "").split("/");
  const m = req.method;
  const body = m === "POST" || m === "PUT" ? await req.json().catch(() => ({})) : {};
  const session = (u) => ({ token: sign({ email: u.email, role: u.role, name: u.name }), user: { email: u.email, name: u.name, role: u.role } });

  if (path[0] === "register" && m === "POST") {
    const email = clean(body.email, 100).toLowerCase();
    if (!email.includes("@") || clean(body.password, 200).length < 8 || !clean(body.name))
      return json({ error: "Enter your name, a valid email and a password of 8+ characters." }, 400);
    if (await store.get("user:" + email)) return json({ error: "That email is already registered." }, 409);
    let role = "student";
    if (body.role === "supervisor") {
      const code = Netlify.env.get("SUPERVISOR_CODE");
      if (!code || body.code !== code) return json({ error: "Supervisor code is incorrect." }, 403);
      role = "supervisor";
    }
    const u = { email, name: clean(body.name, 80), role, pw: hash(String(body.password)) };
    await store.setJSON("user:" + email, u);
    return json(session(u));
  }
  if (path[0] === "login" && m === "POST") {
    const u = await store.get("user:" + clean(body.email, 100).toLowerCase(), { type: "json" });
    if (!u || !same(String(body.password || ""), u.pw)) return json({ error: "Email or password is incorrect." }, 401);
    return json(session(u));
  }

  const me = verify((req.headers.get("authorization") || "").replace("Bearer ", ""));
  if (!me) return json({ error: "Please sign in." }, 401);

  if (path[0] === "supervisors" && m === "GET") {
    const us = (await getAll(store, "user:")).filter((u) => u.role === "supervisor");
    return json(us.map((u) => ({ email: u.email, name: u.name })));
  }

  if (path[0] === "entries") {
    if (m === "GET" && !path[1]) {
      let es = await getAll(store, me.role === "student" ? `entry:${me.email}:` : "entry:");
      if (me.role === "supervisor") es = es.filter((e) => e.supervisor === me.email);
      return json(es.sort((a, b) => b.date.localeCompare(a.date)));
    }
    if (m === "POST" && me.role === "student") {
      const sup = await store.get("user:" + clean(body.supervisor, 100).toLowerCase(), { type: "json" });
      if (!sup || sup.role !== "supervisor") return json({ error: "Choose a supervisor." }, 400);
      if (!clean(body.date) || !clean(body.rotation) || !clean(body.caseType))
        return json({ error: "Date, rotation and case are required." }, 400);
      const id = randomBytes(6).toString("hex");
      const e = {
        id, student: me.email, studentName: me.name, supervisor: sup.email,
        date: clean(body.date, 10), rotation: clean(body.rotation, 80), caseType: clean(body.caseType, 120),
        involvement: ["Observed", "Assisted", "Performed"].includes(body.involvement) ? body.involvement : "Observed",
        learning: clean(body.learning, 1000), status: "pending", comment: "",
      };
      await store.setJSON(`entry:${me.email}:${id}`, e);
      return json(e, 201);
    }
    if (path[1] && path[2]) {
      const key = `entry:${decodeURIComponent(path[1])}:${path[2]}`;
      const e = await store.get(key, { type: "json" });
      if (!e) return json({ error: "Entry not found." }, 404);
      if (m === "PUT" && me.role === "supervisor" && e.supervisor === me.email) {
        if (!["signed", "returned"].includes(body.status)) return json({ error: "Invalid status." }, 400);
        e.status = body.status;
        e.comment = clean(body.comment, 300);
        await store.setJSON(key, e);
        return json(e);
      }
      if (m === "DELETE" && me.role === "student" && e.student === me.email && e.status !== "signed") {
        await store.delete(key);
        return json({ ok: true });
      }
    }
  }
  return json({ error: "Not allowed." }, 403);
};
