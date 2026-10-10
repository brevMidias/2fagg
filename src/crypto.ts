const encoder = new TextEncoder();
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function decodeSecret(secret: string): Uint8Array {
  if (!/^[A-Z2-7]{16,128}$/.test(secret)) throw new Error('Invalid secret');
  let bits = 0, accumulator = 0;
  const result: number[] = [];
  for (const character of secret) {
    accumulator = (accumulator << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) { bits -= 8; result.push((accumulator >>> bits) & 255); }
  }
  if (bits && (accumulator & ((1 << bits) - 1))) throw new Error('Invalid secret');
  if (result.length < 10 || result.length > 80) throw new Error('Invalid secret');
  return Uint8Array.from(result);
}
export async function totp(secret: string, time: number): Promise<string> {
  const key = await crypto.subtle.importKey('raw', decodeSecret(secret), {name:'HMAC',hash:'SHA-1'}, false, ['sign']);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setBigUint64(0, BigInt(Math.floor(time / 30)));
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const offset = signature[signature.length - 1] & 15;
  const value = new DataView(signature.buffer).getUint32(offset) & 0x7fffffff;
  return String(value % 1000000).padStart(6, '0');
}
export async function tokenHash(token: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(token)));
  return Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('');
}
const toBase64 = (data: Uint8Array) => btoa(String.fromCharCode(...data));
const fromBase64 = (data: string) => Uint8Array.from(atob(data), char => char.charCodeAt(0));
async function encryptionKey(value: string) {
  const bytes = fromBase64(value);
  if (bytes.length !== 32 || toBase64(bytes) !== value) throw new Error('Invalid encryption key');
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt','decrypt']);
}
export async function encryptSecret(secret: string, key: string, id: string): Promise<{nonce:string;ciphertext:string}> {
  decodeSecret(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:encoder.encode(id)}, await encryptionKey(key), encoder.encode(secret));
  return {nonce:toBase64(nonce),ciphertext:toBase64(new Uint8Array(ciphertext))};
}
export async function decryptSecret(value: {nonce:string;ciphertext:string}, key: string, id: string): Promise<string> {
  const nonce = fromBase64(value.nonce);
  if (nonce.length !== 12) throw new Error('Invalid nonce');
  const plaintext = await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,additionalData:encoder.encode(id)}, await encryptionKey(key), fromBase64(value.ciphertext));
  const secret = new TextDecoder().decode(plaintext);
  decodeSecret(secret);
  return secret;
}
