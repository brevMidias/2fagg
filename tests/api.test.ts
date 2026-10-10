import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { URL as NodeURL } from 'node:url';
import worker from '../src/index.ts';
import type { Env } from '../src/index.ts';

const id = '72158710-872d-4f3e-aa23-1f94737fe322';
const id2 = '32bffcc3-51ee-4cba-9945-a205e725f210';
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const token = 'AAAAAAAAAAAAAAAAAAAAAA';
const token2 = 'BBBBBBBBBBBBBBBBBBBBBA';
function setup() {
  const database = new DatabaseSync(':memory:');
  database.exec(readFileSync(new NodeURL('../migrations/0001_entries.sql', import.meta.url),'utf8'));
  let blocked = false;
  const env = {
    ADMIN_API_KEY: 'test-admin-key-32-characters-long-only',
    ENCRYPTION_KEY_B64: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    DB: { prepare(sql: string) {
      const statement = database.prepare(sql);
      let args: Array<string|number|null> = [];
      const bound = { bind(...values: Array<string|number|null>) { args = values; return bound; },
        async first() { return statement.get(...args) ?? null; } };
      return bound;
    } },
    REQUEST_LIMITER: { async limit() { return {success: !blocked}; } },
  } as unknown as Env;
  const request = (path: string, method = 'GET', body?: unknown, authorization?: string) => worker.fetch(new Request('https://test.invalid'+path, {
    method, headers:{'Content-Type':'application/json','Authorization':authorization ?? 'Bearer '+env.ADMIN_API_KEY,'CF-Connecting-IP':'192.0.2.1'},
    ...(body === undefined ? {} : {body:JSON.stringify(body)})
  }),env);
  const put = (revision:number, access_token=token, external=id, totpSecret=secret) => request('/api/v1/entries/'+external,'PUT',{secret:totpSecret,access_token,revision});
  const code = (value=token) => request('/api/public/code','POST',undefined,'Bearer '+value);
  return {database,env,request,put,code,block:()=>{blocked=true;}};
}

test('admin authentication, strict fields and body validation fail closed', async () => {
  const s = setup();
  assert.equal((await s.request('/api/v1/entries/'+id,'PUT',{},'Bearer bad')).status,401);
  assert.equal((await s.request('/api/v1/entries/'+id,'PUT',{secret,access_token:token,revision:1,email:'private'})).status,400);
  for (const revision of [0,-1,1.2,'1',Number.MAX_SAFE_INTEGER+1]) {
    assert.equal((await s.request('/api/v1/entries/'+id,'PUT',{secret,access_token:token,revision})).status,400);
  }
  assert.equal((await s.put(1,token,id,'SECRET!')).status,400);
  assert.equal((await s.put(1,'short')).status,400);
  assert.equal((await s.put(1,token,'sequential-1')).status,404);
  s.database.close();
});
test('PUT response contains no secrets, D1 stores ciphertext and same revision is idempotent', async () => {
  const s = setup();
  const response = await s.put(1);
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{revision:1,status:'active'});
  const before = s.database.prepare('SELECT * FROM entries').get();
  assert.ok(before?.ciphertext); assert.notEqual(before?.ciphertext,secret);
  assert.notEqual(before?.token_hash,token);
  assert.equal((await s.put(1)).status,200);
  assert.deepEqual(s.database.prepare('SELECT * FROM entries').get(),before);
  assert.equal((await s.put(1,token2)).status,409);
  s.database.close();
});
test('public tokens are isolated, rotation invalidates old token and stale PUT cannot reverse rotation', async () => {
  const s = setup();
  assert.equal((await s.put(1)).status,200);
  assert.equal((await s.put(1,token2,id2,'JBSWY3DPEHPK3PXP')).status,200);
  const response = await s.code();
  assert.equal(response.status,200);
  const body = await response.json() as {code:string;remaining_seconds:number;server_time:number;valid_until:number};
  assert.deepEqual(Object.keys(body).sort(),['code','remaining_seconds','server_time','valid_until']);
  assert.match(body.code,/^\d{6}$/); assert.equal(body.valid_until,body.server_time+body.remaining_seconds);
  assert.ok(body.remaining_seconds>=1 && body.remaining_seconds<=30);
  assert.equal(response.headers.get('Cache-Control'),'no-store');
  assert.equal((await s.put(2,'CCCCCCCCCCCCCCCCCCCCCA')).status,200);
  assert.equal((await s.code()).status,404);
  assert.equal((await s.code(token2)).status,200);
  assert.equal((await s.put(1)).status,409);
  s.database.close();
});
test('revocation keeps a tombstone, retries succeed and late PUT cannot resurrect entry', async () => {
  const s = setup();
  await s.put(1);
  for (let retry=0;retry<2;retry++) {
    const response=await s.request('/api/v1/entries/'+id,'DELETE',{revision:2});
    assert.equal(response.status,200); assert.deepEqual(await response.json(),{revision:2,status:'revoked'});
  }
  assert.equal((await s.code()).status,404);
  assert.equal((await s.put(1)).status,409);
  assert.equal((await s.put(2)).status,409);
  assert.equal(s.database.prepare('SELECT ciphertext FROM entries').get()?.ciphertext,null);
  assert.equal((await s.request('/api/v1/entries/'+id2,'DELETE',{revision:3})).status,200);
  assert.equal((await s.put(1,token2,id2)).status,409);
  s.database.close();
});
test('duplicate token cannot grant one token access to two accounts', async () => {
  const s=setup(); await s.put(1);
  assert.equal((await s.put(1,token,id2)).status,409);
  assert.equal(s.database.prepare('SELECT count(*) AS n FROM entries').get()?.n,1);
  s.database.close();
});
test('rate limiter rejects before DB reads and missing configuration is unavailable', async () => {
  const s=setup(); await s.put(1); s.block(); s.database.close();
  assert.equal((await s.code()).status,429);
  const unconfigured={...s.env,ENCRYPTION_KEY_B64:''};
  assert.equal((await worker.fetch(new Request('https://test.invalid/api/public/code',{method:'POST',headers:{Authorization:'Bearer '+token}}),unconfigured)).status,503);
});
test('concurrent out of order mutations retain newest revision', async () => {
  const s=setup();
  await Promise.all([s.put(1),s.put(3,token2),s.put(2)]);
  assert.equal(s.database.prepare('SELECT revision FROM entries').get()?.revision,3);
  assert.equal((await s.code()).status,404);
  assert.equal((await s.code(token2)).status,200);
  s.database.close();
});
test('page never includes token, secret or third party assets and sends privacy headers', async () => {
  const s=setup(); const response=await s.request('/c');
  assert.equal(response.status,200);
  assert.equal(response.headers.get('Referrer-Policy'),'no-referrer');
  assert.match(response.headers.get('Content-Security-Policy') ?? '',/default-src 'none'/);
  assert.equal(response.headers.get('Cache-Control'),'no-store');
  const html=await response.text();
  assert.match(html,/Autenticação 2FA/); assert.match(html,/Copiar código/);
  assert.ok(!html.includes(secret)); assert.ok(!html.includes(token));
  s.database.close();
});
