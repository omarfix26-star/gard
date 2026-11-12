/* ============================================================
   سيرفر نظام جرد البضاعة — للاستضافة على Render / Railway / VPS / PC

   ・بيقدّم الواجهة نفسه (index.html جنبه أو داخل المجلد public/)
   ・قاعدة بيانات SQLite في ملف واحد داخل DATA_DIR
   ・مزامنة كل الأجهزة على نفس البيانات + تسجيل مين مسح إيه

   التشغيل محليًا:   npm install  ثم  node server.js
   ============================================================ */
'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

/* bcryptjs اختياري — لو مش متاح نستخدم PBKDF2 المدمج في Node (بدون أي مكتبات native) */
let bcrypt = null;
try { bcrypt = require('bcryptjs'); } catch (e) {}
const hashPass = (p) => bcrypt ? bcrypt.hashSync(String(p), 8) : 'p$' + (() => { const s = crypto.randomBytes(16).toString('hex'); return s + '$' + crypto.pbkdf2Sync(String(p), s, 120000, 32, 'sha256').toString('hex'); })();
const checkPass = (p, h) => {
  if (!h) return false;
  if (h.startsWith('p$')) { const [, s, k] = h.split('$'); return crypto.timingSafeEqual(Buffer.from(k, 'hex'), crypto.pbkdf2Sync(String(p), s, 120000, 32, 'sha256')); }
  return bcrypt ? bcrypt.compareSync(String(p), h) : false;
};

const PORT = process.env.PORT || 3000;
const COMPANY = (process.env.COMPANY || 'main').trim();
const ADMIN_USER = (process.env.ADMIN_USER || 'admin').trim().toLowerCase();
const ADMIN_PASS = process.env.PASSWORD || '12345678';
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

/* sql.js (WebAssembly) أولًا — تشتغل على أي استضافة بدون مشاكل بناء، وبعدها better-sqlite3 */
let db, saveDb = () => {};
const DB_FILE = path.join(DATA_DIR, 'inventory.db');
let sqljs = null;
try { sqljs = require('sql.js'); } catch (e) {}
let NativeDb = null;
try { NativeDb = require('better-sqlite3'); } catch (e) {}

async function openDb() {
  if (sqljs) {
    const SQL = await sqljs({ locateFile: (f) => path.join(path.dirname(require.resolve('sql.js')), f) });
    const buf = fs.existsSync(DB_FILE) ? fs.readFileSync(DB_FILE) : null;
    const d = buf ? new SQL.Database(buf) : new SQL.Database();
    let dirty = false, timer = null;
    /* تصدير آمن: لو فيه معاملة مفتوحة أو الملف مشغول نأجل الحفظ للجولة اللي بعدها */
    let busy = false;
    const saveNow = () => {
      if (busy || !dirty) return;
      busy = true;
      try {
        fs.writeFileSync(DB_FILE + '.tmp', Buffer.from(d.export()));
        fs.renameSync(DB_FILE + '.tmp', DB_FILE);
        dirty = false;
      } catch (e) { /* الملف مشغول — نحاول تاني بعد شوية */ }
      busy = false;
    };
    const bye = () => { saveNow(); process.exit(0); };
    process.on('SIGTERM', bye);
    process.on('SIGINT', bye);
    const q = (sql, params) => {
      const st = d.prepare(sql); st.bind(params || []);
      const rows = []; while (st.step()) rows.push(st.getAsObject()); st.free(); return rows;
    };
    db = {
      _sqljs: true,
      prepare: (sql) => ({
        run: (...a) => { d.run(sql, a); dirty = true; if (/^\s*(INSERT|UPDATE|DELETE|CREATE|DROP)/i.test(sql)) saveNow(); },
        get: (...a) => q(sql, a)[0],
        all: (...a) => q(sql, a)
      }),
      exec: (sql) => { d.run(sql); dirty = true; },
      transaction: (fn) => (...a) => { d.run('BEGIN'); try { const r = fn(...a); d.run('COMMIT'); dirty = true; saveNow(); return r; } catch (e) { try { d.run('ROLLBACK'); } catch (_) {} throw e; } },
      pragma: () => {},
      close: () => saveNow(),
      flush: () => saveNow()
    };
    setInterval(saveNow, 1000);
    console.log('🗄️  قاعدة البيانات: SQLite (WebAssembly, ملف: ' + DB_FILE + ')');
    return;
  }
  if (!NativeDb) { console.error('❌ شغّل الأول: npm install'); process.exit(1); }
  const nd = new NativeDb(DB_FILE);
  nd.pragma('journal_mode = WAL');
  nd.pragma('busy_timeout = 5000');
  db = nd;
  console.log('🗄️  قاعدة البيانات: better-sqlite3 (ملف: ' + DB_FILE + ')');
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS companies(code TEXT PRIMARY KEY, name TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS centers(code TEXT, company TEXT, name TEXT, open INTEGER DEFAULT 0, opened_by TEXT, opened_at TEXT, PRIMARY KEY(code, company));
CREATE TABLE IF NOT EXISTS users(username TEXT, company TEXT, pass TEXT, name TEXT, role TEXT, center TEXT, active INTEGER DEFAULT 1, created_at TEXT, PRIMARY KEY(username, company));
CREATE TABLE IF NOT EXISTS items(company TEXT, center TEXT, barcode TEXT, name TEXT, price REAL DEFAULT 0, qty REAL DEFAULT 0, by_user TEXT, by_name TEXT, last TEXT, PRIMARY KEY(company, center, barcode));
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT, company TEXT, ts TEXT, ev TEXT, det TEXT, by_user TEXT, by_name TEXT);
CREATE TABLE IF NOT EXISTS sessions(tid TEXT PRIMARY KEY, username TEXT, company TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, company TEXT, center TEXT, barcode TEXT, qty REAL, user TEXT, name TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS idx_items ON items(company, center);
CREATE INDEX IF NOT EXISTS idx_logs ON logs(company, id);
`;

const now = () => new Date().toISOString();
const log = (company, ev, det, user) => {
  try { db.prepare('INSERT INTO logs(company,ts,ev,det,by_user,by_name) VALUES(?,?,?,?,?,?)')
    .run(company, now(), ev, det || '', (user && user.username) || '', (user && user.name) || ''); } catch (e) {}
};
const out = (u) => u ? { username: u.username, name: u.name, role: u.role, center: u.center, active: !!u.active, company: u.company } : null;
const compFrom = (req) => String(req.headers['x-company'] || COMPANY).trim() || COMPANY;
const itemOut = (it) => ({ barcode: it.barcode, name: it.name, price: it.price, qty: it.qty, by_user: it.by_user, by_name: it.by_name, last: it.last });

function ensureCompany(code) {
  let c = db.prepare('SELECT * FROM companies WHERE code=?').get(code);
  if (!c) {
    db.prepare('INSERT INTO companies(code,name,created_at) VALUES(?,?,?)').run(code, code === COMPANY ? 'الشركة الرئيسية' : code, now());
    c = db.prepare('SELECT * FROM companies WHERE code=?').get(code);
  }
  if (!db.prepare('SELECT 1 FROM centers WHERE company=?').get(code)) {
    db.prepare('INSERT INTO centers(code,company,name,open) VALUES(?,?,?,0)').run('MAIN', code, 'الفرع الرئيسي');
  }
  return c;
}

function ensureAdmin() {
  ensureCompany(COMPANY);
  const u = db.prepare("SELECT * FROM users WHERE company=? AND role='admin'").get(COMPANY);
  if (!u) {
    db.prepare('INSERT INTO users(username,company,pass,name,role,center,active,created_at) VALUES(?,?,?,?,?,?,1,?)')
      .run(ADMIN_USER, COMPANY, bcrypt.hashSync(ADMIN_PASS, 8), 'مدير النظام', 'admin', 'MAIN', now());
    console.log('✅ حساب المدير: ' + ADMIN_USER + ' / ' + ADMIN_PASS + '   (كود الشركة: ' + COMPANY + ')');
    console.log('   ⚠️ غيّر كلمة السر من تبويب المستخدمين بعد أول دخول.');
  }
}

const app = express();
app.use((req, res, next) => { ready.then(() => next()).catch(next); });
app.use(express.json({ limit: '3mb' }));

/* ---------- الواجهة ---------- */
const CANDIDATES = [
  path.join(__dirname, 'index.html'),
  path.join(process.cwd(), 'index.html'),
  path.join(process.cwd(), 'public', 'index.html'),
  path.join(__dirname, 'public', 'index.html')
];
function pageFile() { for (const f of CANDIDATES) { if (fs.existsSync(f)) return f; } return null; }
app.use(express.static(process.cwd(), { index: false, maxAge: 0 }));
app.get(['/', '/index.html'], (req, res) => {
  const f = pageFile();
  if (f) return res.set('Cache-Control', 'no-store').sendFile(f);
  res.status(200).type('html').send('<h3 style="font-family:sans-serif;padding:24px">السيرفر شغال ✅<br><small>حط ملف <b>index.html</b> جنب server.js.</small></h3>');
});

/* ---------- المصادقة ---------- */
app.post('/api/login', (req, res) => {
  const company = compFrom(req);
  ensureCompany(company);
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ message: 'invalid' });
  const u = db.prepare('SELECT * FROM users WHERE company=? AND username=?').get(company, String(username).trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(password), u.pass)) return res.status(401).json({ message: 'invalid_credentials' });
  if (!u.active) return res.status(403).json({ message: 'account_disabled' });
  const tid = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions(tid,username,company,created_at) VALUES(?,?,?,?)').run(tid, u.username, company, now());
  log(company, 'تسجيل دخول', u.username, u);
  res.json({ token: tid, user: out(u) });
});

function auth(req, res, next) {
  const h = String(req.headers.authorization || '');
  const tid = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!tid) return res.status(401).json({ message: 'unauthorized' });
  const s = db.prepare('SELECT * FROM sessions WHERE tid=?').get(tid);
  if (!s) return res.status(401).json({ message: 'unauthorized' });
  const u = db.prepare('SELECT * FROM users WHERE company=? AND username=?').get(s.company, s.username);
  if (!u || !u.active) return res.status(401).json({ message: 'unauthorized' });
  req.user = u; req.company = s.company; req.tid = tid;
  next();
}

app.post('/api/logout', auth, (req, res) => { db.prepare('DELETE FROM sessions WHERE tid=?').run(req.tid); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: out(req.user) }));
app.get('/api/health', (req, res) => res.json({ ok: true, company: COMPANY, time: now() }));

app.get('/api/items', auth, (req, res) => {
  const center = String(req.query.center || req.user.center);
  res.json(db.prepare('SELECT * FROM items WHERE company=? AND center=? ORDER BY last DESC').all(req.company, center).map(itemOut));
});

app.get('/api/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'forbidden' });
  res.json(db.prepare('SELECT * FROM users WHERE company=? ORDER BY created_at ASC').all(req.company).map(out));
});

app.get('/api/centers', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM centers WHERE company=? ORDER BY code ASC').all(req.company).map(c => ({ code: c.code, name: c.name, open: !!c.open })));
});

app.get('/api/log', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'forbidden' });
  const lim = Math.min(500, parseInt(req.query.limit || '200', 10) || 200);
  res.json(db.prepare('SELECT * FROM logs WHERE company=? ORDER BY id DESC LIMIT ?').all(req.company, lim));
});

/* مين مسح كام */
app.get('/api/stats', auth, (req, res) => {
  const center = String(req.query.center || req.user.center);
  res.json(db.prepare('SELECT user as u, name as n, COUNT(*) c, COALESCE(SUM(qty),0) q FROM scans WHERE company=? AND center=? GROUP BY user ORDER BY c DESC').all(req.company, center));
});

function mustAdmin(req) { if (req.user.role !== 'admin') { const e = new Error('forbidden'); e.status = 403; throw e; } }

const rpcs = {
  center_state(req) {
    const p = req.body || {};
    const center = p.p_center || req.user.center;
    const c = db.prepare('SELECT * FROM centers WHERE company=? AND code=?').get(req.company, center) || {};
    const agg = db.prepare('SELECT COUNT(*) n, COALESCE(SUM(qty),0) u, COALESCE(SUM(qty*price),0) v FROM items WHERE company=? AND center=?').get(req.company, center);
    return { open: !!c.open, by: c.opened_by || '', at: c.opened_at || '', items: agg.n, units: agg.u, value: agg.v };
  },

  scan_batch(req) {
    const p = req.body || {};
    const center = p.p_center || req.user.center;
    if (req.user.role !== 'admin') {
      if (req.user.role !== 'scanner') throw Object.assign(new Error('forbidden'), { status: 403 });
      const c = db.prepare('SELECT * FROM centers WHERE company=? AND code=?').get(req.company, center);
      if (!c || !c.open) throw Object.assign(new Error('closed'), { status: 409 });
    }
    const up = db.prepare(`INSERT INTO items(company,center,barcode,name,price,qty,by_user,by_name,last)
      VALUES(?,?,?,'',0,?,?,?,?) ON CONFLICT(company,center,barcode) DO UPDATE SET
      qty = items.qty + ?, by_user=?, by_name=?, last=?`);
    const addScan = db.prepare('INSERT INTO scans(company,center,barcode,qty,user,name,ts) VALUES(?,?,?,?,?,?,?)');
    const list = (Array.isArray(p.p_codes) ? p.p_codes : []).filter(x => x && x.barcode);
    const tx = db.transaction(() => {
      for (const x of list) {
        const code = String(x.barcode), q = Number(x.qty) || 1, ts = now();
        up.run(req.company, center, code, q, req.user.username, req.user.name, ts, q, req.user.username, req.user.name, ts);
        addScan.run(req.company, center, code, q, req.user.username, req.user.name, ts);
      }
    });
    tx();
    return { ok: true, count: list.length };
  },

  set_item(req) {
    const p = req.body || {};
    const center = p.p_center || req.user.center;
    const barcode = String(p.p_barcode || '');
    if (!barcode) throw Object.assign(new Error('bad_request'), { status: 400 });
    const ex = db.prepare('SELECT * FROM items WHERE company=? AND center=? AND barcode=?').get(req.company, center, barcode);
    if (!ex) {
      db.prepare('INSERT INTO items(company,center,barcode,name,price,qty,by_user,by_name,last) VALUES(?,?,?,?,?,?,?,?,?)')
        .run(req.company, center, barcode, p.p_name || '', Number(p.p_price) || 0, Number(p.p_qty) || 0, req.user.username, req.user.name, now());
    } else {
      db.prepare('UPDATE items SET name=?, price=?, qty=?, by_user=?, by_name=?, last=? WHERE company=? AND center=? AND barcode=?')
        .run(p.p_name == null ? ex.name : p.p_name, p.p_price == null ? ex.price : Number(p.p_price), p.p_qty == null ? ex.qty : Number(p.p_qty), req.user.username, req.user.name, now(), req.company, center, barcode);
    }
    return { ok: true };
  },

  del_item(req) {
    mustAdmin(req);
    const p = req.body || {};
    db.prepare('DELETE FROM items WHERE company=? AND center=? AND barcode=?').run(req.company, p.p_center || req.user.center, String(p.p_barcode || ''));
    return { ok: true };
  },

  clear_items(req) {
    mustAdmin(req);
    const p = req.body || {};
    const center = p.p_center || req.user.center;
    db.prepare('DELETE FROM items WHERE company=? AND center=?').run(req.company, center);
    db.prepare('DELETE FROM scans WHERE company=? AND center=?').run(req.company, center);
    log(req.company, 'تفريغ الجرد', 'المركز: ' + center, req.user);
    return { ok: true };
  },

  set_session(req) {
    mustAdmin(req);
    const p = req.body || {};
    const center = String(p.p_center || req.user.center);
    if (p.p_open) {
      db.prepare('UPDATE centers SET open=1, opened_by=?, opened_at=? WHERE company=? AND code=?').run(req.user.name, now(), req.company, center);
      log(req.company, 'فتح الجرد', 'المركز: ' + center, req.user);
    } else {
      db.prepare('UPDATE centers SET open=0 WHERE company=? AND code=?').run(req.company, center);
      log(req.company, 'إغلاق الجرد', 'المركز: ' + center, req.user);
    }
    return { ok: true };
  },

  create_user(req) {
    mustAdmin(req);
    const p = req.body || {};
    const username = String(p.p_username || '').trim().toLowerCase();
    if (!username || !p.p_password || String(p.p_password).length < 6) throw Object.assign(new Error('bad_request'), { status: 400 });
    if (db.prepare('SELECT 1 FROM users WHERE company=? AND username=?').get(req.company, username)) throw Object.assign(new Error('user_exists'), { status: 409 });
    db.prepare('INSERT INTO users(username,company,pass,name,role,center,active,created_at) VALUES(?,?,?,?,?,?,1,?)')
      .run(username, req.company, bcrypt.hashSync(String(p.p_password), 8), p.p_name || username, p.p_role || 'scanner', p.p_center || 'MAIN', now());
    log(req.company, 'إضافة مستخدم', username, req.user);
    return { ok: true };
  },

  update_user(req) {
    mustAdmin(req);
    const p = req.body || {};
    const username = String(p.p_username || '').toLowerCase();
    const u = db.prepare('SELECT * FROM users WHERE company=? AND username=?').get(req.company, username);
    if (!u) throw Object.assign(new Error('not_found'), { status: 404 });
    if (p.p_active === false && username === req.user.username) throw Object.assign(new Error('cannot_disable_self'), { status: 400 });
    db.prepare('UPDATE users SET name=?, role=?, center=?, active=? WHERE company=? AND username=?')
      .run(p.p_name == null ? u.name : p.p_name, p.p_role == null ? u.role : p.p_role, p.p_center == null ? u.center : p.p_center, p.p_active == null ? u.active : (p.p_active ? 1 : 0), req.company, username);
    return { ok: true };
  },

  set_password(req) {
    mustAdmin(req);
    const p = req.body || {};
    const username = String(p.p_username || '').toLowerCase();
    if (!p.p_password || String(p.p_password).length < 6) throw Object.assign(new Error('bad_request'), { status: 400 });
    db.prepare('UPDATE users SET pass=? WHERE company=? AND username=?').run(bcrypt.hashSync(String(p.p_password), 8), req.company, username);
    db.prepare('DELETE FROM sessions WHERE company=? AND username=?').run(req.company, username);
    return { ok: true };
  },

  delete_user(req) {
    mustAdmin(req);
    const p = req.body || {};
    const username = String(p.p_username || '').toLowerCase();
    if (username === req.user.username) throw Object.assign(new Error('cannot_delete_self'), { status: 400 });
    db.prepare('DELETE FROM users WHERE company=? AND username=?').run(req.company, username);
    db.prepare('DELETE FROM sessions WHERE company=? AND username=?').run(req.company, username);
    log(req.company, 'حذف مستخدم', username, req.user);
    return { ok: true };
  },

  add_center(req) {
    mustAdmin(req);
    const p = req.body || {};
    const code = String(p.p_code || '').trim().toUpperCase();
    if (!code || !p.p_name) throw Object.assign(new Error('bad_request'), { status: 400 });
    if (db.prepare('SELECT 1 FROM centers WHERE company=? AND code=?').get(req.company, code)) throw Object.assign(new Error('center_exists'), { status: 409 });
    db.prepare('INSERT INTO centers(code,company,name,open) VALUES(?,?,?,0)').run(code, req.company, p.p_name);
    log(req.company, 'إضافة مركز', code + ' — ' + p.p_name, req.user);
    return { ok: true };
  },

  del_center(req) {
    mustAdmin(req);
    const p = req.body || {};
    const code = String(p.p_code || '').toUpperCase();
    if (db.prepare('SELECT 1 FROM users WHERE company=? AND center=?').get(req.company, code)) throw Object.assign(new Error('center_has_users'), { status: 400 });
    db.prepare('DELETE FROM centers WHERE company=? AND code=?').run(req.company, code);
    db.prepare('DELETE FROM items WHERE company=? AND center=?').run(req.company, code);
    return { ok: true };
  }
};

app.post('/api/rpc/:fn', auth, (req, res) => {
  const fn = rpcs[req.params.fn];
  if (!fn) return res.status(404).json({ message: 'unknown_function' });
  try { res.json(fn(req) || { ok: true }); }
  catch (e) { res.status(e.status || 400).json({ message: e.message }); }
});

const ready = (async () => {
  await openDb();
  db.exec(SCHEMA);
  ensureAdmin();
  return app;
})();

module.exports = { app, ready, get db() { return db; } };
if (require.main === module) {
  ready.then(() => app.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 السيرفر شغال على المنفذ ' + PORT);
    console.log('   كود الشركة: ' + COMPANY + ' | ملف البيانات: ' + DB_FILE);
    console.log('   افتح المتصفح على: http://localhost:' + PORT);
  })).catch(e => { console.error('❌ فشل التشغيل:', e); process.exit(1); });
}
