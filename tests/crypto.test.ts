import { test } from 'node:test';
import assert from 'node:assert/strict';
import { totp, encryptSecret, decryptSecret, tokenHash } from '../src/crypto.ts';

const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));

test('RFC 6238 SHA1 vectors yield six digit codes', async () => {
  for (const [time, code] of [[59,'287082'],[1111111109,'081804'],[1111111111,'050471'],[1234567890,'005924'],[2000000000,'279037'],[20000000000,'353130']] as const) {
    assert.equal(await totp(secret, time), code);
  }
});
test('AES GCM binds entry identity, randomizes nonce and detects tampering', async () => {
  const a = await encryptSecret(secret, key, 'entry-a');
  const b = await encryptSecret(secret, key, 'entry-a');
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.ciphertext, b.ciphertext);
  assert.equal(await decryptSecret(a, key, 'entry-a'), secret);
  await assert.rejects(decryptSecret(a, key, 'entry-b'));
  await assert.rejects(decryptSecret({...a, ciphertext: a.ciphertext.slice(0,-4) + 'AAAA'}, key, 'entry-a'));
  await assert.rejects(encryptSecret(secret, 'bad', 'entry-a'));
});
test('token hashes match SHA256 and invalid base32 fails closed', async () => {
  assert.equal(await tokenHash('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  await assert.rejects(totp('invalid!secret', 59));
});
