import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const sig = (e) => crypto.createHmac("sha256", process.env.ADMIN_PASSWORD || "").update(String(e)).digest("hex");
const valid = (t) => {
  if (!process.env.ADMIN_PASSWORD || !t) return false;
  const [e, s] = t.split(".");
  if (!e || !s || +e < Date.now()) return false;
  const a = Buffer.from(s), b = Buffer.from(sig(e));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

export default async (req) => {
  const p = new URL(req.url).pathname.replace(/^\/api\//, "").split("/");
  const m = req.method;
  const db = getStore("studio"), photos = getStore("photos");

  if (p[0] === "content" && m === "GET") return J(await db.get("content", { type: "json" }));

  if (p[0] === "login" && m === "POST") {
    const { password } = await req.json().catch(() => ({}));
    const w = process.env.ADMIN_PASSWORD;
    const h = (x) => crypto.createHash("sha256").update(String(x)).digest();
    if (!w || !crypto.timingSafeEqual(h(password || ""), h(w))) {
      await new Promise((r) => setTimeout(r, 1200));
      return J({ error: "Contraseña incorrecta" }, 401);
    }
    const e = Date.now() + 12 * 3600e3;
    return J({ token: e + "." + sig(e) });
  }

  if (p[0] === "photo" && m === "GET") {
    const r = await photos.getWithMetadata(p[1], { type: "arrayBuffer" });
    if (!r) return new Response("", { status: 404 });
    return new Response(r.data, { headers: { "content-type": r.metadata?.type || "image/jpeg", "cache-control": "public, max-age=31536000, immutable" } });
  }

  const rv = getStore("reviews");
  const rl = async () => (await rv.get("all", { type: "json" })) || [];
  if (p[0] === "reviews" && m === "GET") {
    const all = await rl();
    const adm = valid(req.headers.get("x-token")) && new URL(req.url).searchParams.get("all");
    return J(adm ? all : all.filter((r) => r.show).map(({ n, t, r, ts }) => ({ n, t, r, ts })));
  }
  if (p[0] === "review" && m === "POST") {
    const b = await req.json().catch(() => ({}));
    if (b.hp) return J({ ok: 1 });
    const n = String(b.n || "").trim().slice(0, 60), t = String(b.t || "").trim().slice(0, 600), r = Math.round(+b.r);
    if (!n || t.length < 5 || !(r >= 1 && r <= 5)) return J({ error: "Completa tu nombre, tu opinión y las estrellas" }, 400);
    const all = await rl();
    if (all.length >= 300) return J({ error: "Intenta más tarde" }, 429);
    all.unshift({ id: crypto.randomUUID(), n, t, r, ts: Date.now(), show: false });
    await rv.setJSON("all", all);
    return J({ ok: 1 });
  }

  if (!valid(req.headers.get("x-token"))) return J({ error: "Sesión vencida, entra de nuevo" }, 401);

  if (p[0] === "content" && m === "PUT") {
    const t = await req.text();
    if (t.length > 200000) return J({ error: "Demasiado grande" }, 413);
    let d; try { d = JSON.parse(t); } catch { return J({ error: "Datos inválidos" }, 400); }
    await db.setJSON("content", d);
    return J({ ok: 1 });
  }

  if (p[0] === "upload" && m === "POST") {
    const t = req.headers.get("content-type") || "";
    if (!/^image\/(jpeg|png|webp)$/.test(t)) return J({ error: "Solo imágenes" }, 415);
    const buf = await req.arrayBuffer();
    if (buf.byteLength > 6e6) return J({ error: "Foto muy pesada" }, 413);
    const id = crypto.randomUUID();
    await photos.set(id, buf, { metadata: { type: t } });
    return J({ id });
  }

  if (p[0] === "photo" && m === "DELETE") { await photos.delete(p[1]); return J({ ok: 1 }); }
  if (p[0] === "review" && (m === "PATCH" || m === "DELETE")) {
    let all = await rl();
    if (m === "DELETE") all = all.filter((x) => x.id !== p[1]);
    else { const b = await req.json().catch(() => ({})); all = all.map((x) => (x.id === p[1] ? { ...x, show: !!b.show } : x)); }
    await rv.setJSON("all", all);
    return J({ ok: 1 });
  }

  return J({ error: "No encontrado" }, 404);
};

export const config = { path: "/api/*" };
