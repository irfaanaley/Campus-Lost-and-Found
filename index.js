// Campus Lost & Found - Vercel serverless function (Node.js + Postgres).
// The frontend calls /api/index?r=<route>, for example /api/index?r=me
const crypto = require('crypto');
const { Pool } = require('pg');
const PAGE = require('../lib/page.js'); // the website (HTML) is bundled into this function

// ------------------------------------------------------------ database
let pool = null;
let ready = null;

function dbUrl() {
  return process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_URL_NON_POOLING || '';
}

function getPool() {
  if (!pool) pool = new Pool({ connectionString: dbUrl(), max: 3 });
  return pool;
}

async function q(sql, params = []) {
  return (await getPool().query(sql, params)).rows;
}

async function tx(fn) {
  const c = await getPool().connect();
  try {
    await c.query('BEGIN');
    const r = await fn((sql, params = []) => c.query(sql, params).then((x) => x.rows));
    await c.query('COMMIT');
    return r;
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally {
    c.release();
  }
}

function init() {
  if (!ready) {
    ready = (async () => {
      const stmts = [
        'CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT UNIQUE, "full" TEXT, role TEXT, contact TEXT, salt TEXT, hash TEXT)',
        'CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid INTEGER, exp DOUBLE PRECISION)',
        'CREATE TABLE IF NOT EXISTS items(id SERIAL PRIMARY KEY, name TEXT, category TEXT, location TEXT, date TEXT, finder TEXT, status TEXT, color TEXT, brand TEXT, marks TEXT, photo TEXT)',
        'CREATE TABLE IF NOT EXISTS claims(id SERIAL PRIMARY KEY, item_id INTEGER, uid INTEGER, claimant TEXT, contact TEXT, color TEXT, brand TEXT, marks TEXT, proof TEXT, cnic TEXT, selfie TEXT, extra TEXT, status TEXT, detail TEXT, code TEXT, created DOUBLE PRECISION, decided DOUBLE PRECISION)',
        'CREATE TABLE IF NOT EXISTS files(name TEXT PRIMARY KEY, data BYTEA)',
      ];
      for (const s of stmts) await q(s);
    })().catch((e) => { ready = null; throw e; });
  }
  return ready;
}

// ------------------------------------------------------------ helpers
const FAILS = new Map();
const now = () => Date.now() / 1000;
const clean = (s, n = 200) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim().slice(0, n);
const toks = (s) => String(s).toLowerCase().match(/[a-z0-9]+/g) || [];
const isAdm = (u) => !!u && (u.role === 'admin' || u.role === 'owner');
const hp = (pw, salt) => crypto.pbkdf2Sync(pw, Buffer.from(salt, 'hex'), 200000, 32, 'sha256').toString('hex');

function fuzzy(a, b) {
  a = String(a || '').trim().toLowerCase();
  b = String(b || '').trim().toLowerCase();
  if (!a || !b) return false;
  if (a === b || b.includes(a) || a.includes(b)) return true;
  const bt = toks(b);
  return toks(a).some((t) => t.length >= 3 && bt.includes(t));
}

async function saveImg(run, data) {
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(data || '');
  if (!m) return null;
  const raw = Buffer.from(m[1], 'base64');
  if (raw.length > 2500000 || raw[0] !== 0xff || raw[1] !== 0xd8) return null;
  const name = crypto.randomBytes(16).toString('hex') + '.jpg';
  await run('INSERT INTO files(name,data) VALUES($1,$2)', [name, raw]);
  return name;
}

function send(res, code, obj, opt = {}) {
  const body = opt.raw !== undefined ? opt.raw : Buffer.from(JSON.stringify(obj));
  res.statusCode = code;
  res.setHeader('Content-Type', opt.ctype || 'application/json');
  res.setHeader('Content-Length', body.length);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  if (opt.cookie) res.setHeader('Set-Cookie', opt.cookie);
  res.end(body);
}

async function readBody(req) {
  let text = '';
  if (req.readableEnded) {
    const b = req.body;
    if (b && typeof b === 'object' && !Buffer.isBuffer(b)) return b;
    text = b ? b.toString() : '';
  } else {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > 12 * 1024 * 1024) throw Object.assign(new Error('Request too large'), { status: 413 });
      chunks.push(c);
    }
    text = Buffer.concat(chunks).toString();
  }
  if (!text) return {};
  try {
    const o = JSON.parse(text);
    return o && typeof o === 'object' ? o : {};
  } catch (_) {
    throw Object.assign(new Error('Bad request'), { status: 400 });
  }
}

function cookieSid(req) {
  const m = /(?:^|;\s*)sid=([0-9a-f]+)/.exec(req.headers.cookie || '');
  return m ? m[1] : null;
}

async function currentUser(req) {
  const sid = cookieSid(req);
  if (!sid) return null;
  const s = (await q('SELECT * FROM sessions WHERE token=$1 AND exp>$2', [sid, now()]))[0];
  if (!s) return null;
  return (await q('SELECT * FROM users WHERE id=$1', [s.uid]))[0] || null;
}

async function makeUser(res, b, role, cur) {
  if (role === 'admin' && !isAdm(cur)) return send(res, 403, { error: 'Only admins can create admins.' });
  const full = clean(b.full), un = clean(b.username).toLowerCase(), ct = clean(b.contact, 60), pw = String(b.password || '');
  if (!full || !un || !pw) return send(res, 400, { error: 'Please fill in all the fields.' });
  if (role === 'user' && !ct) return send(res, 400, { error: 'Please enter a phone number or student ID.' });
  if (!/^[a-z0-9_.]{3,20}$/.test(un)) return send(res, 400, { error: 'Username must be 3-20 characters: letters, numbers, _ or .' });
  if (pw.length < 6) return send(res, 400, { error: 'Password must be at least 6 characters.' });
  if (pw !== b.password2) return send(res, 400, { error: 'The two passwords do not match.' });
  if ((await q('SELECT 1 FROM users WHERE username=$1', [un])).length) return send(res, 400, { error: 'That username is already taken.' });
  const salt = crypto.randomBytes(16).toString('hex');
  await q('INSERT INTO users(username,"full",role,contact,salt,hash) VALUES($1,$2,$3,$4,$5,$6)', [un, full, role, ct, salt, hp(pw, salt)]);
  return send(res, 200, { ok: 1, username: un });
}

// ------------------------------------------------------------ routes
async function ping(res) {
  const info = {
    node: process.version,
    framework: 'node',
    db_env: !!dbUrl(),
  };
  if (!dbUrl()) {
    info.db = 'Postgres is not connected: in Vercel open Storage, connect Neon, then Redeploy.';
  } else {
    try { await init(); info.db = 'ok'; } catch (e) { info.db = String(e.message).slice(0, 300); }
  }
  return send(res, 200, info);
}

async function route(req, res, m, p, b) {
  if (!dbUrl()) return send(res, 500, { error: 'Database not connected. In Vercel open Storage, connect a Postgres database, then Redeploy.' });
  await init();
  const u = await currentUser(req);
  const P = p.split('/').slice(2);
  const secure = String(req.headers['x-forwarded-proto'] || '').startsWith('https') ? '; Secure' : '';
  const hasAdmin = (await q("SELECT 1 FROM users WHERE role IN('admin','owner')")).length > 0;

  if (p === '/api/me') {
    return send(res, 200, { user: u ? { username: u.username, full: u.full, role: u.role, contact: u.contact } : null, setup: !hasAdmin });
  }
  if ((p === '/api/setup' || p === '/api/register') && m === 'POST') {
    let role = 'user';
    if (p === '/api/setup') {
      if (hasAdmin) return send(res, 403, { error: 'Owner setup is closed.' });
      role = 'owner';
    }
    return makeUser(res, b, role, u);
  }
  if (p === '/api/login' && m === 'POST') {
    const un = clean(b.username).toLowerCase();
    const ip = String(req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '').split(',')[0].trim();
    const key = un + '|' + ip;
    let f = FAILS.get(key) || [0, 0];
    if (now() < f[1]) return send(res, 429, { error: 'Too many attempts. Wait ' + Math.ceil(f[1] - now()) + ' seconds.' });
    const r = (await q('SELECT * FROM users WHERE username=$1', [un]))[0];
    if (!r || hp(String(b.password || ''), r.salt) !== r.hash) {
      f[0] += 1;
      if (f[0] >= 5) f = [0, now() + 30];
      FAILS.set(key, f);
      return send(res, 401, { error: 'Incorrect username or password.' });
    }
    FAILS.delete(key);
    const t = crypto.randomBytes(24).toString('hex');
    await q('INSERT INTO sessions(token,uid,exp) VALUES($1,$2,$3)', [t, r.id, now() + 86400 * 7]);
    return send(res, 200, { ok: 1 }, { cookie: 'sid=' + t + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800' + secure });
  }

  if (!u) return send(res, 401, { error: 'Please log in.' });

  if (p === '/api/logout') {
    await q('DELETE FROM sessions WHERE uid=$1', [u.id]);
    return send(res, 200, { ok: 1 }, { cookie: 'sid=; Max-Age=0; Path=/; HttpOnly' + secure });
  }

  if (P[0] === 'file') { // item photos: any member. Claim proofs: admins and the claimant only
    if (P.length < 2) return send(res, 404, { error: 'Not found' });
    const n = P[1].split('/').pop();
    let ok = (await q('SELECT 1 FROM items WHERE photo=$1', [n])).length > 0;
    if (!ok) {
      const c = (await q('SELECT uid FROM claims WHERE cnic=$1 OR selfie=$1 OR extra=$1', [n]))[0];
      ok = !!c && (isAdm(u) || c.uid === u.id);
    }
    const fr = ok ? (await q('SELECT data FROM files WHERE name=$1', [n]))[0] : null;
    return fr ? send(res, 200, null, { raw: Buffer.from(fr.data), ctype: 'image/jpeg' }) : send(res, 404, { error: 'Not found' });
  }

  if (P[0] === 'items') {
    if (m === 'GET') return send(res, 200, await q('SELECT id,name,category,location,date,finder,status,photo FROM items ORDER BY id'));
    const need = ['name', 'location', 'color', 'brand', 'marks'].map((k) => clean(b[k]));
    if (!need.every(Boolean)) return send(res, 400, { error: 'Please fill in every field, including the private details.' });
    const ph = b.photo ? await saveImg(q, b.photo) : null;
    const r = await q("INSERT INTO items(name,category,location,date,finder,status,color,brand,marks,photo) VALUES($1,$2,$3,$4,$5,'FOUND',$6,$7,$8,$9) RETURNING id",
      [need[0], clean(b.category, 30), need[1], clean(b.date, 10), u.full, need[2], need[3], need[4], ph]);
    return send(res, 200, { id: r[0].id });
  }

  if (P[0] === 'claims') {
    if (m === 'POST' && P.length === 1) {
      if (u.role !== 'user') return send(res, 403, { error: 'Only user accounts can submit claims.' });
      const it = (await q('SELECT * FROM items WHERE id=$1', [parseInt(b.item_id, 10) || 0]))[0];
      if (!it) return send(res, 404, { error: 'No item found with this ID.' });
      if (it.status !== 'FOUND') return send(res, 400, { error: 'This item is no longer available.' });
      if ((await q("SELECT 1 FROM claims WHERE item_id=$1 AND uid=$2 AND status='PENDING'", [it.id, u.id])).length)
        return send(res, 400, { error: 'You already have a pending claim for this item.' });
      const a = ['color', 'brand', 'marks'].map((k) => clean(b[k]));
      if (!a.every(Boolean)) return send(res, 400, { error: 'Please answer color, brand/model and marks.' });
      const cn = await saveImg(q, b.cnic), se = await saveImg(q, b.selfie);
      const ex = b.extra ? await saveImg(q, b.extra) : null;
      if (!cn || !se) return send(res, 400, { error: 'Owner proof is required: a photo of your CNIC / student card and a clear photo of yourself.' });
      const r = await q("INSERT INTO claims(item_id,uid,claimant,contact,color,brand,marks,proof,cnic,selfie,extra,status,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PENDING',$12) RETURNING id",
        [it.id, u.id, u.full, clean(b.contact, 60) || u.contact, a[0], a[1], a[2], clean(b.proof), cn, se, ex, now()]);
      return send(res, 200, { id: r[0].id });
    }
    if (P[1] === 'mine') {
      return send(res, 200, await q('SELECT c.id,c.status,c.detail,c.code,c.item_id,i.name FROM claims c JOIN items i ON i.id=c.item_id WHERE c.uid=$1 ORDER BY c.id DESC', [u.id]));
    }
    if (!isAdm(u)) return send(res, 403, { error: 'Admins only.' });
    if (m === 'GET') {
      const out = await q('SELECT c.*,i.name iname,i.color icolor,i.brand ibrand,i.marks imarks,i.finder,i.location,i.date FROM claims c JOIN items i ON i.id=c.item_id ORDER BY c.id');
      for (const c of out) {
        c.score = ['color', 'brand', 'marks'].filter((x) => fuzzy(c[x], c['i' + x])).length;
        delete c.uid;
      }
      return send(res, 200, out);
    }
    if (P.length < 3) return send(res, 404, { error: 'Not found' });
    const cid = parseInt(P[1], 10);
    if (!cid) return send(res, 400, { error: 'Bad claim id.' });
    const c = (await q('SELECT * FROM claims WHERE id=$1', [cid]))[0];
    if (!c) return send(res, 404, { error: 'Claim not found.' });
    if (P[2] === 'decide') {
      if (c.status !== 'PENDING') return send(res, 400, { error: 'Already decided.' });
      const it = (await q('SELECT * FROM items WHERE id=$1', [c.item_id]))[0];
      if (b.approve && it.status !== 'FOUND') return send(res, 400, { error: 'Item is not available.' });
      await tx(async (run) => {
        if (b.approve) {
          const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
          await run("UPDATE claims SET status='APPROVED',detail='Approved. Bring your original ID to the admin office and show the handover code.',code=$1,decided=$2 WHERE id=$3", [code, now(), c.id]);
          await run("UPDATE items SET status='CLAIMED' WHERE id=$1", [it.id]);
          await run("UPDATE claims SET status='REJECTED',detail='Another claim for this item was approved.',decided=$1 WHERE item_id=$2 AND status='PENDING'", [now(), it.id]);
        } else {
          await run("UPDATE claims SET status='REJECTED',detail=$1,decided=$2 WHERE id=$3", ['Rejected: ' + (clean(b.note) || 'details did not match.'), now(), c.id]);
        }
      });
      return send(res, 200, { ok: 1 });
    }
    if (P[2] === 'handover') { // item leaves only when code + ID are verified in person
      if (c.status !== 'APPROVED' || clean(b.code) !== c.code || !b.id_checked) return send(res, 400, { error: 'Wrong code, or ID not confirmed.' });
      await tx(async (run) => {
        await run("UPDATE claims SET status='RETURNED',detail='Item handed over to the verified owner.' WHERE id=$1", [c.id]);
        await run("UPDATE items SET status='RETURNED' WHERE id=$1", [c.item_id]);
      });
      return send(res, 200, { ok: 1 });
    }
  }

  if (P[0] === 'users') {
    if (!isAdm(u)) return send(res, 403, { error: 'Admins only.' });
    if (m === 'GET') return send(res, 200, await q('SELECT username,"full",role,contact,(SELECT COUNT(*) FROM claims WHERE uid=users.id)::int n FROM users'));
    if (m === 'POST' && P.length === 1) return makeUser(res, b, 'admin', u);
    if (P.length < 2) return send(res, 404, { error: 'Not found' });
    const t = (await q('SELECT * FROM users WHERE username=$1', [P[1]]))[0];
    if (!t || t.id === u.id || t.role === 'owner') return send(res, 400, { error: 'Not allowed on this account.' });
    if (m === 'DELETE') {
      if (t.role === 'admin' && u.role !== 'owner') return send(res, 403, { error: 'Only the owner can delete an admin.' });
      await tx(async (run) => {
        await run('DELETE FROM users WHERE id=$1', [t.id]);
        await run('DELETE FROM sessions WHERE uid=$1', [t.id]);
      });
    } else {
      const nr = b.role;
      if (nr === 'user' && u.role !== 'owner') return send(res, 403, { error: 'Only the owner can remove admin rights.' });
      if (nr !== 'user' && nr !== 'admin') return send(res, 400, { error: 'Unknown role.' });
      await q('UPDATE users SET role=$1 WHERE id=$2', [nr, t.id]);
    }
    return send(res, 200, { ok: 1 });
  }

  return send(res, 404, { error: 'Not found' });
}

module.exports = async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const r = url.searchParams.get('r');
    if (r === null) { // no ?r= means a normal page visit: serve the website
      if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
      return send(res, 200, null, { raw: Buffer.from(PAGE), ctype: 'text/html; charset=utf-8' });
    }
    const p = '/api/' + r;
    if (p === '/api/ping') return await ping(res);
    const m = req.method;
    const b = m === 'POST' ? await readBody(req) : {};
    return await route(req, res, m, p, b);
  } catch (e) {
    return send(res, e.status || 500, { error: e.status ? e.message : 'Server error: ' + e.message });
  }
};
