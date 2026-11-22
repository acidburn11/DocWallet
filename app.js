import { deriveKey, encryptBytes, decryptBytes, randomBytes, toB64, fromB64 } from './crypto.js';

const IDLE_MS = 3 * 60 * 1000;
const te = new TextEncoder(), td = new TextDecoder();
const VERIFIER = 'DOCWALLET-OK';
const $ = id => document.getElementById(id);
let key = null, idleTimer = null, viewUrl = null, dbp = null;

// ---------- IndexedDB ----------
function openDb() {
  dbp ??= new Promise((res, rej) => {
    const r = indexedDB.open('docwallet', 1);
    r.onupgradeneeded = () => {
      r.result.createObjectStore('meta');
      r.result.createObjectStore('files', { keyPath: 'id' });
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  return dbp;
}
const req = r => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
async function store(name, write = false) {
  return (await openDb()).transaction(name, write ? 'readwrite' : 'readonly').objectStore(name);
}
const getMeta = async k => req((await store('meta')).get(k));
const setMeta = async (k, v) => req((await store('meta', true)).put(v, k));
const allFiles = async () => req((await store('files')).getAll());
const putFile = async rec => req((await store('files', true)).put(rec));
const delFile = async id => req((await store('files', true)).delete(id));

// ---------- seif ----------
async function unlock(pass) {
  const meta = await getMeta('vault');
  if (!meta) {
    const salt = randomBytes(16);
    const k = await deriveKey(pass, salt);
    const v = await encryptBytes(k, te.encode(VERIFIER), 'verifier');
    await setMeta('vault', { salt: toB64(salt), verifier: v });
    key = k;
    return;
  }
  const k = await deriveKey(pass, fromB64(meta.salt));
  try {
    const pt = await decryptBytes(k, meta.verifier, 'verifier');
    if (td.decode(pt) !== VERIFIER) throw new Error();
  } catch { throw new Error('Parola gresita'); }
  key = k;
}

async function fileMeta(r) {
  return JSON.parse(td.decode(await decryptBytes(key, { iv: r.miv, ct: r.mct }, r.id + ':m')));
}
async function fileBytes(r) {
  return decryptBytes(key, { iv: r.iv, ct: r.ct }, r.id);
}

async function addFiles(files) {
  for (const f of files) {
    const id = crypto.randomUUID();
    const e = await encryptBytes(key, await f.arrayBuffer(), id);
    const m = await encryptBytes(key, te.encode(JSON.stringify({ name: f.name, mime: f.type, size: f.size })), id + ':m');
    await putFile({ id, added: Date.now(), iv: e.iv, ct: e.ct, miv: m.iv, mct: m.ct });
  }
  await render();
}

async function render() {
  const list = $('list');
  list.textContent = '';
  const recs = (await allFiles()).sort((a, b) => b.added - a.added);
  for (const r of recs) {
    const m = await fileMeta(r);
    const li = document.createElement('li');
    const open = document.createElement('button');
    open.textContent = m.name;
    open.onclick = () => openFile(r);
    const del = document.createElement('button');
    del.textContent = 'Sterge';
    del.className = 'danger';
    del.onclick = async () => {
      if (confirm(`Stergi ${m.name}?`)) { await delFile(r.id); render(); }
    };
    li.append(open, del);
    list.append(li);
  }
  $('status').textContent = `${recs.length} documente`;
}

async function openFile(r) {
  const m = await fileMeta(r);
  const bytes = await fileBytes(r);
  closeViewer();
  viewUrl = URL.createObjectURL(new Blob([bytes], { type: m.mime || 'application/octet-stream' }));
  const body = $('viewBody');
  if ((m.mime || '').startsWith('image/')) {
    const img = document.createElement('img');
    img.src = viewUrl;
    body.append(img);
  } else {
    const fr = document.createElement('iframe');
    fr.src = viewUrl;
    body.append(fr);
  }
  $('viewer').classList.remove('hidden');
}

function closeViewer() {
  if (viewUrl) URL.revokeObjectURL(viewUrl);
  viewUrl = null;
  $('viewBody').textContent = '';
  $('viewer').classList.add('hidden');
}

// ---------- backup / restore (doar date criptate) ----------
async function backup() {
  const payload = { v: 1, vault: await getMeta('vault'), files: await allFiles() };
  const name = `backup-${new Date().toISOString().slice(0, 10)}.enc`;
  const file = new File([JSON.stringify(payload)], name, { type: 'application/octet-stream' });
  try {
    if (navigator.canShare?.({ files: [file] })) {
      await navigator.share({ files: [file], title: 'DocWallet backup' });
    } else {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(file);
      a.download = name;
      a.click();
    }
    $('status').textContent = 'Backup creat';
  } catch (e) {
    if (e.name !== 'AbortError') $('status').textContent = 'Eroare backup: ' + e.message;
  }
}

async function restore(file) {
  const data = JSON.parse(await file.text());
  if (data.v !== 1) throw new Error('Format necunoscut');
  const local = await getMeta('vault');
  if (!local) await setMeta('vault', data.vault);
  else if (local.salt !== data.vault.salt) throw new Error('Backup-ul apartine altui seif');
  for (const r of data.files) await putFile(r);
}

// ---------- ecrane si blocare ----------
function show(id) {
  for (const s of ['auth', 'app']) $(s).classList.toggle('hidden', s !== id);
  if (id !== 'app') closeViewer();
}

async function start() {
  const setup = !(await getMeta('vault'));
  $('pass2').classList.toggle('hidden', !setup);
  $('authHint').textContent = setup
    ? 'Creeaza o parola (minim 12 caractere). Nu are recuperare: noteaz-o pe hartie.'
    : 'Introdu parola ca sa deschizi seiful.';
  $('authBtn').textContent = setup ? 'Creeaza seif' : 'Deschide';
  $('authErr').textContent = '';
  show('auth');
}

async function openApp() {
  show('app');
  await render();
  resetIdle();
}

function lock() {
  key = null;
  clearTimeout(idleTimer);
  start();
}

function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, IDLE_MS);
}

// ---------- evenimente ----------
$('authBtn').onclick = async () => {
  $('authErr').textContent = '';
  const p = $('pass').value;
  try {
    if (!$('pass2').classList.contains('hidden')) {
      if (p.length < 12) throw new Error('Minim 12 caractere');
      if (p !== $('pass2').value) throw new Error('Parolele nu coincid');
    }
    await unlock(p);
    $('pass').value = '';
    $('pass2').value = '';
    await openApp();
  } catch (e) {
    $('authErr').textContent = e.message;
  }
};

$('restore').onchange = async e => {
  const f = e.target.files[0];
  e.target.value = '';
  if (!f) return;
  try {
    await restore(f);
    await start();
    $('authErr').textContent = 'Backup restaurat. Introdu parola.';
  } catch (err) {
    $('authErr').textContent = err.message;
  }
};

$('upload').onchange = async e => {
  try { await addFiles(e.target.files); } finally { e.target.value = ''; }
};
$('backupBtn').onclick = backup;
$('lockBtn').onclick = lock;
$('closeViewer').onclick = closeViewer;

['pointerdown', 'keydown', 'touchstart'].forEach(ev =>
  document.addEventListener(ev, () => { if (key) resetIdle(); }, { passive: true }));

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js');
start();
