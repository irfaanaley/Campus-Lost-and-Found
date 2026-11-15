"""Campus Lost & Found - Flask web app.

Local:   pip install -r requirements.txt  ->  python api/index.py  ->  http://localhost:8000
Vercel:  import the GitHub repo, connect Postgres (Neon) from the Storage tab, then Redeploy.
Database: Postgres when DATABASE_URL / POSTGRES_URL is set, otherwise a local SQLite file (local use only).
"""
import os, re, json, time, base64, hashlib, secrets, threading, sys, sqlite3
from flask import Flask, request, Response, send_from_directory

try:
    import psycopg2, psycopg2.extras
    IMPERR = ''
except Exception as e:
    psycopg2 = None
    IMPERR = str(e)
NETERR = (psycopg2.OperationalError, psycopg2.InterfaceError) if psycopg2 else ()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = os.path.join(ROOT, 'public')
ON_VERCEL = bool(os.environ.get('VERCEL'))
LOCK = threading.Lock()
FAILS = {}

app = Flask(__name__)


def pg_url():
    return os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL') or os.environ.get('POSTGRES_URL_NON_POOLING')


# ---------------------------------------------------------------- database
class R:
    def __init__(s, cur, lid=None): s.cur, s.lastrowid = cur, lid
    def fetchone(s): return s.cur.fetchone()
    def __iter__(s): return iter(s.cur.fetchall())


class DB:
    c = None

    def is_pg(s): return bool(pg_url())

    def connect(s):
        if s.is_pg():
            if psycopg2 is None: raise RuntimeError('psycopg2 missing: ' + IMPERR)
            return psycopg2.connect(pg_url())
        c = sqlite3.connect(os.path.join(ROOT, 'lostfound.db'), check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def execute(s, sql, a=()):
        pg = s.is_pg()
        if pg: sql = sql.replace('?', '%s')
        ret = pg and bool(re.match(r'\s*INSERT INTO (items|claims)', sql))
        if ret: sql += ' RETURNING id'
        for attempt in (1, 2):
            try:
                if s.c is None or (pg and s.c.closed): s.c = s.connect()
                cur = s.c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) if pg else s.c.cursor()
                cur.execute(sql, a)
                lid = cur.fetchone()['id'] if ret else (None if pg else cur.lastrowid)
                return R(cur, lid)
            except NETERR:
                s.c = None
                if attempt == 2: raise
            except Exception:
                try:
                    if s.c is not None: s.c.rollback()
                except Exception: s.c = None
                raise

    def commit(s): s.c.commit()


db = DB()
INIT = []


def init():
    if INIT: return
    pg = db.is_pg()
    pk = 'SERIAL PRIMARY KEY' if pg else 'INTEGER PRIMARY KEY AUTOINCREMENT'
    ts = 'DOUBLE PRECISION' if pg else 'REAL'
    blob = 'BYTEA' if pg else 'BLOB'
    for q in [
        'CREATE TABLE IF NOT EXISTS users(id %s, username TEXT UNIQUE, "full" TEXT, role TEXT, contact TEXT, salt TEXT, hash TEXT)' % pk,
        'CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid INTEGER, exp %s)' % ts,
        'CREATE TABLE IF NOT EXISTS items(id %s, name TEXT, category TEXT, location TEXT, date TEXT, finder TEXT, status TEXT, color TEXT, brand TEXT, marks TEXT, photo TEXT)' % pk,
        'CREATE TABLE IF NOT EXISTS claims(id %s, item_id INTEGER, uid INTEGER, claimant TEXT, contact TEXT, color TEXT, brand TEXT, marks TEXT, proof TEXT, cnic TEXT, selfie TEXT, extra TEXT, status TEXT, detail TEXT, code TEXT, created %s, decided %s)' % (pk, ts, ts),
        'CREATE TABLE IF NOT EXISTS files(name TEXT PRIMARY KEY, data %s)' % blob,
    ]:
        db.execute(q)
    db.commit()
    INIT.append(1)


# ---------------------------------------------------------------- helpers
def hp(pw, salt): return hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), 200000).hex()
def clean(s, n=200): return re.sub(r'\s+', ' ', str(s or '')).strip()[:n]
def toks(s): return re.findall(r'[a-z0-9]+', s.lower())


def fuzzy(a, b):
    a, b = (a or '').strip().lower(), (b or '').strip().lower()
    if not a or not b: return False
    if a == b or a in b or b in a: return True
    return any(len(t) >= 3 and t in toks(b) for t in toks(a))


def save_img(data):
    m = re.match(r'^data:image/jpeg;base64,(.+)$', data or '')
    if not m: return None
    raw = base64.b64decode(m.group(1))
    if len(raw) > 2_500_000 or raw[:2] != b'\xff\xd8': return None
    n = secrets.token_hex(16) + '.jpg'
    db.execute("INSERT INTO files VALUES(?,?)", (n, psycopg2.Binary(raw) if db.is_pg() else raw))
    return n


def rows(sql, *a): return [dict(r) for r in db.execute(sql, a)]
def isadm(u): return bool(u) and u['role'] in ('admin', 'owner')


def out(code, obj=None, raw=None, ctype='application/json', cookie=None):
    body = raw if raw is not None else json.dumps(obj).encode()
    r = Response(body, status=code, content_type=ctype)
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['Cache-Control'] = 'no-store'
    if cookie: r.headers.add('Set-Cookie', cookie)
    return r


def secure_flag():
    https = request.is_secure or request.headers.get('X-Forwarded-Proto', '').startswith('https')
    return '; Secure' if https else ''


def current_user():
    m = re.search(r'sid=([0-9a-f]+)', request.headers.get('Cookie', ''))
    if not m: return None
    s = db.execute("SELECT * FROM sessions WHERE token=? AND exp>?", (m.group(1), time.time())).fetchone()
    if not s: return None
    u = db.execute("SELECT * FROM users WHERE id=?", (s['uid'],)).fetchone()
    return dict(u) if u else None


def make_user(b, role, cur):
    if role == 'admin' and not isadm(cur): return out(403, {'error': 'Only admins can create admins.'})
    full, un, ct, pw = clean(b.get('full')), clean(b.get('username')).lower(), clean(b.get('contact'), 60), str(b.get('password', ''))
    if not full or not un or not pw: return out(400, {'error': 'Please fill in all the fields.'})
    if role == 'user' and not ct: return out(400, {'error': 'Please enter a phone number or student ID.'})
    if not re.match(r'^[a-z0-9_.]{3,20}$', un): return out(400, {'error': 'Username must be 3-20 characters: letters, numbers, _ or .'})
    if len(pw) < 6: return out(400, {'error': 'Password must be at least 6 characters.'})
    if pw != b.get('password2'): return out(400, {'error': 'The two passwords do not match.'})
    if db.execute("SELECT 1 FROM users WHERE username=?", (un,)).fetchone(): return out(400, {'error': 'That username is already taken.'})
    s = secrets.token_hex(16)
    db.execute('INSERT INTO users(username,"full",role,contact,salt,hash) VALUES(?,?,?,?,?,?)', (un, full, role, ct, s, hp(pw, s)))
    db.commit()
    return out(200, {'ok': 1, 'username': un})


# ---------------------------------------------------------------- routes
def ping():
    info = {'python': sys.version[:6], 'framework': 'flask', 'psycopg2': 'ok' if psycopg2 else IMPERR,
            'db_env': bool(pg_url()), 'db_type': 'postgres' if pg_url() else 'sqlite (local)'}
    if ON_VERCEL and not pg_url():
        info['db'] = 'Postgres is not connected: in Vercel open Storage, connect Neon, then Redeploy.'
    else:
        try:
            init(); info['db'] = 'ok'
        except Exception as e:
            info['db'] = str(e)[:300]
    return out(200, info)


def route(m, p, b):
    if ON_VERCEL and not pg_url():
        return out(500, {'error': 'Database not connected. In Vercel open Storage, connect a Postgres database, then Redeploy.'})
    init()
    u = current_user()
    P = p.split('/')[2:]
    has_admin = db.execute("SELECT 1 FROM users WHERE role IN('admin','owner')").fetchone() is not None

    if p == '/api/me':
        return out(200, {'user': u and {k: u[k] for k in ('username', 'full', 'role', 'contact')}, 'setup': not has_admin})
    if p in ('/api/setup', '/api/register') and m == 'POST':
        role = 'user'
        if p == '/api/setup':
            if has_admin: return out(403, {'error': 'Owner setup is closed.'})
            role = 'owner'
        return make_user(b, role, u)
    if p == '/api/login' and m == 'POST':
        un = clean(b.get('username')).lower()
        ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()
        key = (un, ip); f = FAILS.get(key, [0, 0])
        if time.time() < f[1]: return out(429, {'error': 'Too many attempts. Wait %d seconds.' % (f[1] - time.time())})
        r = db.execute("SELECT * FROM users WHERE username=?", (un,)).fetchone()
        if not r or hp(str(b.get('password', '')), r['salt']) != r['hash']:
            f[0] += 1
            if f[0] >= 5: f = [0, time.time() + 30]
            FAILS[key] = f
            return out(401, {'error': 'Incorrect username or password.'})
        FAILS.pop(key, None)
        t = secrets.token_hex(24)
        db.execute("INSERT INTO sessions VALUES(?,?,?)", (t, r['id'], time.time() + 86400 * 7)); db.commit()
        return out(200, {'ok': 1}, cookie='sid=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800%s' % (t, secure_flag()))

    if not u: return out(401, {'error': 'Please log in.'})

    if p == '/api/logout':
        db.execute("DELETE FROM sessions WHERE uid=?", (u['id'],)); db.commit()
        return out(200, {'ok': 1}, cookie='sid=; Max-Age=0; Path=/; HttpOnly' + secure_flag())

    if P[0] == 'file':   # item photos: any member. Claim proofs: admins and the claimant only
        if len(P) < 2: return out(404, {'error': 'Not found'})
        n = os.path.basename(P[1])
        ok = db.execute("SELECT 1 FROM items WHERE photo=?", (n,)).fetchone()
        if not ok:
            c = db.execute("SELECT uid FROM claims WHERE cnic=? OR selfie=? OR extra=?", (n, n, n)).fetchone()
            ok = c and (isadm(u) or c['uid'] == u['id'])
        fr = db.execute("SELECT data FROM files WHERE name=?", (n,)).fetchone() if ok else None
        return out(200, raw=bytes(fr['data']), ctype='image/jpeg') if fr else out(404, {'error': 'Not found'})

    if P[0] == 'items':
        if m == 'GET':
            return out(200, rows("SELECT id,name,category,location,date,finder,status,photo FROM items ORDER BY id"))
        need = [clean(b.get(k)) for k in ('name', 'location', 'color', 'brand', 'marks')]
        if not all(need): return out(400, {'error': 'Please fill in every field, including the private details.'})
        ph = save_img(b['photo']) if b.get('photo') else None
        c = db.execute("INSERT INTO items(name,category,location,date,finder,status,color,brand,marks,photo) VALUES(?,?,?,?,?,'FOUND',?,?,?,?)",
                       (need[0], clean(b.get('category'), 30), need[1], clean(b.get('date'), 10), u['full'], need[2], need[3], need[4], ph))
        db.commit()
        return out(200, {'id': c.lastrowid})

    if P[0] == 'claims':
        if m == 'POST' and len(P) == 1:
            if u['role'] != 'user': return out(403, {'error': 'Only user accounts can submit claims.'})
            it = db.execute("SELECT * FROM items WHERE id=?", (int(b.get('item_id') or 0),)).fetchone()
            if not it: return out(404, {'error': 'No item found with this ID.'})
            if it['status'] != 'FOUND': return out(400, {'error': 'This item is no longer available.'})
            if db.execute("SELECT 1 FROM claims WHERE item_id=? AND uid=? AND status='PENDING'", (it['id'], u['id'])).fetchone():
                return out(400, {'error': 'You already have a pending claim for this item.'})
            a = [clean(b.get(k)) for k in ('color', 'brand', 'marks')]
            if not all(a): return out(400, {'error': 'Please answer color, brand/model and marks.'})
            cn, se = save_img(b.get('cnic')), save_img(b.get('selfie'))
            ex = save_img(b.get('extra')) if b.get('extra') else None
            if not cn or not se: return out(400, {'error': 'Owner proof is required: a photo of your CNIC / student card and a clear photo of yourself.'})
            c = db.execute("INSERT INTO claims(item_id,uid,claimant,contact,color,brand,marks,proof,cnic,selfie,extra,status,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,'PENDING',?)",
                           (it['id'], u['id'], u['full'], clean(b.get('contact'), 60) or u['contact'], *a, clean(b.get('proof')), cn, se, ex, time.time()))
            db.commit()
            return out(200, {'id': c.lastrowid})
        if len(P) > 1 and P[1] == 'mine':
            return out(200, rows("SELECT c.id,c.status,c.detail,c.code,c.item_id,i.name FROM claims c JOIN items i ON i.id=c.item_id WHERE c.uid=? ORDER BY c.id DESC", u['id']))
        if not isadm(u): return out(403, {'error': 'Admins only.'})
        if m == 'GET':
            res = rows("SELECT c.*,i.name iname,i.color icolor,i.brand ibrand,i.marks imarks,i.finder,i.location,i.date FROM claims c JOIN items i ON i.id=c.item_id ORDER BY c.id")
            for c in res:
                c['score'] = sum(fuzzy(c[x], c['i' + x]) for x in ('color', 'brand', 'marks')); c.pop('uid')
            return out(200, res)
        if len(P) < 3: return out(404, {'error': 'Not found'})
        try: cid = int(P[1])
        except ValueError: return out(400, {'error': 'Bad claim id.'})
        c = db.execute("SELECT * FROM claims WHERE id=?", (cid,)).fetchone()
        if not c: return out(404, {'error': 'Claim not found.'})
        if P[2] == 'decide':
            if c['status'] != 'PENDING': return out(400, {'error': 'Already decided.'})
            it = db.execute("SELECT * FROM items WHERE id=?", (c['item_id'],)).fetchone()
            if b.get('approve') and it['status'] != 'FOUND': return out(400, {'error': 'Item is not available.'})
            if b.get('approve'):
                code = '%06d' % secrets.randbelow(10 ** 6)
                db.execute("UPDATE claims SET status='APPROVED',detail='Approved. Bring your original ID to the admin office and show the handover code.',code=?,decided=? WHERE id=?", (code, time.time(), c['id']))
                db.execute("UPDATE items SET status='CLAIMED' WHERE id=?", (it['id'],))
                db.execute("UPDATE claims SET status='REJECTED',detail='Another claim for this item was approved.',decided=? WHERE item_id=? AND status='PENDING'", (time.time(), it['id']))
            else:
                db.execute("UPDATE claims SET status='REJECTED',detail=?,decided=? WHERE id=?", ('Rejected: ' + (clean(b.get('note')) or 'details did not match.'), time.time(), c['id']))
            db.commit()
            return out(200, {'ok': 1})
        if P[2] == 'handover':   # item leaves only when code + ID are verified in person
            if c['status'] != 'APPROVED' or clean(b.get('code')) != c['code'] or not b.get('id_checked'):
                return out(400, {'error': 'Wrong code, or ID not confirmed.'})
            db.execute("UPDATE claims SET status='RETURNED',detail='Item handed over to the verified owner.' WHERE id=?", (c['id'],))
            db.execute("UPDATE items SET status='RETURNED' WHERE id=?", (c['item_id'],))
            db.commit()
            return out(200, {'ok': 1})

    if P[0] == 'users':
        if not isadm(u): return out(403, {'error': 'Admins only.'})
        if m == 'GET':
            return out(200, rows('SELECT username,"full",role,contact,(SELECT COUNT(*) FROM claims WHERE uid=users.id) n FROM users'))
        if m == 'POST' and len(P) == 1: return make_user(b, 'admin', u)
        if len(P) < 2: return out(404, {'error': 'Not found'})
        t = db.execute("SELECT * FROM users WHERE username=?", (P[1],)).fetchone()
        if not t or t['id'] == u['id'] or t['role'] == 'owner': return out(400, {'error': 'Not allowed on this account.'})
        if m == 'DELETE':
            if t['role'] == 'admin' and u['role'] != 'owner': return out(403, {'error': 'Only the owner can delete an admin.'})
            db.execute("DELETE FROM users WHERE id=?", (t['id'],)); db.execute("DELETE FROM sessions WHERE uid=?", (t['id'],))
        else:
            nr = b.get('role')
            if nr == 'user' and u['role'] != 'owner': return out(403, {'error': 'Only the owner can remove admin rights.'})
            if nr not in ('user', 'admin'): return out(400, {'error': 'Unknown role.'})
            db.execute("UPDATE users SET role=? WHERE id=?", (nr, t['id']))
        db.commit()
        return out(200, {'ok': 1})

    return out(404, {'error': 'Not found'})


@app.route('/api/index', methods=['GET', 'POST', 'DELETE'])
@app.route('/api/<path:sub>', methods=['GET', 'POST', 'DELETE'])
def api(sub=''):
    try:
        r = request.args.get('r')
        p = '/api/' + (r if r is not None else ('' if sub == 'index' else sub))
        if p == '/api/ping': return ping()
        b = {}
        if request.method == 'POST':
            try: b = json.loads(request.get_data() or b'{}')
            except Exception: return out(400, {'error': 'Bad request'})
            if not isinstance(b, dict): return out(400, {'error': 'Bad request'})
        with LOCK:
            return route(request.method, p, b)
    except Exception as e:
        return out(500, {'error': 'Server error: %s' % e})


@app.route('/')
def home():   # On Vercel public/index.html is served statically; this route is only used when running locally
    return send_from_directory(PUBLIC, 'index.html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    print('Campus Lost & Found is running at http://localhost:%d' % port)
    app.run(host='0.0.0.0', port=port)
