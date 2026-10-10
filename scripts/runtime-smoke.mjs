import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Miniflare, Log, LogLevel, convertV4MiniflareOptions } from 'miniflare';

const mf=new Miniflare(convertV4MiniflareOptions({
  modules:true,scriptPath:'.dry-run/index.js',compatibilityDate:'2026-10-10',
  log:new Log(LogLevel.ERROR),d1Databases:['DB'],
  bindings:{ADMIN_API_KEY:'test-admin-key-32-characters-long-only',ENCRYPTION_KEY_B64:Buffer.alloc(32,7).toString('base64')},
  ratelimits:{REQUEST_LIMITER:{namespace_id:'726201',simple:{limit:30,period:60}}}
}));
try {
  const database=await mf.getD1Database('DB');
  const migration=await readFile('migrations/0001_entries.sql','utf8');
  for(const sql of migration.split(';').filter(value=>value.trim())) await database.prepare(sql).run();
  const id='72158710-872d-4f3e-aa23-1f94737fe322';
  const token='AAAAAAAAAAAAAAAAAAAAAA';
  const request=(path,method,body,bearer='test-admin-key-32-characters-long-only')=>mf.dispatchFetch('https://test.invalid'+path,{
    method,headers:{'Content-Type':'application/json',Authorization:'Bearer '+bearer,'CF-Connecting-IP':'192.0.2.1'},...(body===undefined ? {} : {body:JSON.stringify(body)})
  });
  const payload={secret:'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',access_token:token,revision:1};
  for(let retry=0;retry<2;retry++) {
    const response=await request('/api/v1/entries/'+id,'PUT',payload);
    assert.equal(response.status,200); assert.deepEqual(await response.json(),{revision:1,status:'active'});
  }
  assert.equal((await request('/api/public/code','POST',undefined,token)).status,200);
  assert.equal((await request('/api/v1/entries/'+id,'DELETE',{revision:2})).status,200);
  assert.equal((await request('/api/v1/entries/'+id,'PUT',payload)).status,409);
  assert.equal((await request('/api/public/code','POST',undefined,token)).status,404);
  console.log('Local workerd + D1 smoke passed: create, retry, public code, revoke and stale PUT. Synthetic data only.');
} finally { await mf.dispose(); }
