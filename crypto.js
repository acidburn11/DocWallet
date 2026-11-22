const ITER = 600000;
const te = new TextEncoder();

export const randomBytes = n => crypto.getRandomValues(new Uint8Array(n));

export function toB64(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromB64(str) {
  const s = atob(str);
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b.buffer;
}

// cheia nu poate fi exportata (extractable = false)
export async function deriveKey(pass, salt) {
  const base = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// aad leaga cifrarea de un id, ca blocurile sa nu poata fi schimbate intre ele
export async function encryptBytes(key, data, aad) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, key, data);
  return { iv: toB64(iv), ct: toB64(ct) };
}

export function decryptBytes(key, rec, aad) {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(rec.iv), additionalData: te.encode(aad) },
    key,
    fromB64(rec.ct)
  );
}
