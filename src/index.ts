import { decodeSecret, decryptSecret, encryptSecret, tokenHash, totp } from './crypto.ts';
import { html, css, purchaseCss, script } from './page.ts';

export interface Env {
  DB: D1Database;
  REQUEST_LIMITER: RateLimit;
  ADMIN_API_KEY: string;
  ENCRYPTION_KEY_B64: string;
}
interface Entry { id:string; revision:number; status:'active'|'revoked'; operation_hash:string; token_hash:string|null; ciphertext:string|null; nonce:string|null; key_version:number; }
const tokenPattern = /^[A-Za-z0-9_-]{21}[AQgw]$/;
const entryPattern = /^\/api\/v1\/entries\/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const privacyHeaders = {
  'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer', 'X-Content-Type-Options':'nosniff',
  'X-Robots-Tag':'noindex, nofollow, noarchive',
  'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security':'max-age=31536000'
};
function json(value: unknown,status=200) {
  return new Response(JSON.stringify(value),{status,headers:{...privacyHeaders,'Content-Type':'application/json; charset=utf-8',...(status===429 ? {'Retry-After':'60'} : {})}});
}
function error(status: number) { return json({error: status===409 ? 'revision_conflict' : status===429 ? 'rate_limited' : status===503 ? 'unavailable' : 'invalid_request'},status); }
function bearer(request: Request) { return /^Bearer ([A-Za-z0-9_-]{1,128})$/.exec(request.headers.get('Authorization') ?? '')?.[1] ?? ''; }
async function constantEqual(a:string,b:string) {
  const [left,right] = await Promise.all([tokenHash(a),tokenHash(b)]);
  let different=0;
  for(let index=0;index<left.length;index++) different |= left.charCodeAt(index)^right.charCodeAt(index);
  return different===0;
}
async function readBody(request: Request): Promise<Record<string,unknown>> {
  if(request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json') throw new Error('Invalid body');
  if(Number(request.headers.get('Content-Length') ?? 0)>2048 || !request.body) throw new Error('Invalid body');
  const reader=request.body.getReader(); let total=0; const chunks:Uint8Array[]=[];
  try {
    while(true) { const {value,done}=await reader.read(); if(done) break; total+=value.byteLength; if(total>2048) { await reader.cancel(); throw new Error('Invalid body'); } chunks.push(value); }
  } finally { reader.releaseLock(); }
  const bytes=new Uint8Array(total); let offset=0;
  for(const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.byteLength; }
  const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
  if(!value || typeof value!=='object' || Array.isArray(value)) throw new Error('Invalid body');
  return value as Record<string,unknown>;
}
function configured(env:Env) {
  return !!env.DB && !!env.REQUEST_LIMITER && /^[A-Za-z0-9_-]{32,128}$/.test(env.ADMIN_API_KEY ?? '') && /^[A-Za-z0-9+/]{43}=$/.test(env.ENCRYPTION_KEY_B64 ?? '');
}
async function mutate(request:Request,env:Env,id:string) {
  if(!await constantEqual(bearer(request),env.ADMIN_API_KEY)) return error(401);
  let body:Record<string,unknown>;
  try { body=await readBody(request); } catch { return error(400); }
  const fields=request.method==='PUT' ? ['secret','access_token','revision'] : ['revision'];
  if(Object.keys(body).length!==fields.length || Object.keys(body).some(key=>!fields.includes(key)) || !Number.isSafeInteger(body.revision) || (body.revision as number)<1) return error(400);
  const revision=body.revision as number;
  const status=request.method==='PUT' ? 'active' : 'revoked';
  let hash:string|null=null, ciphertext:string|null=null, nonce:string|null=null;
  if(status==='active') {
    if(typeof body.access_token!=='string' || !tokenPattern.test(body.access_token) || typeof body.secret!=='string') return error(400);
    try { decodeSecret(body.secret); } catch { return error(400); }
    hash=await tokenHash(body.access_token);
    const encrypted=await encryptSecret(body.secret,env.ENCRYPTION_KEY_B64,id);
    ciphertext=encrypted.ciphertext; nonce=encrypted.nonce;
  }
  // Digest covers the entire operation. Same revision with different data is a conflict.
  const operationHash=await tokenHash(JSON.stringify([id,revision,status,body.secret ?? null,body.access_token ?? null]));
  try {
    const result=await env.DB.prepare(`INSERT INTO entries(id,revision,status,operation_hash,token_hash,ciphertext,nonce,key_version,updated_at)
      VALUES(?,?,?,?,?,?,?,1,?) ON CONFLICT(id) DO UPDATE SET
      revision=excluded.revision,status=excluded.status,operation_hash=excluded.operation_hash,
      token_hash=excluded.token_hash,ciphertext=excluded.ciphertext,nonce=excluded.nonce,key_version=1,updated_at=excluded.updated_at
      WHERE excluded.revision > entries.revision RETURNING revision,status`).bind(id,revision,status,operationHash,hash,ciphertext,nonce,Math.floor(Date.now()/1000)).first<{revision:number;status:string}>();
    if(result) return json(result);
  } catch (failure) {
    // Unique token collision must not overwrite either account. Other failures are unavailable.
    if(failure instanceof Error && /UNIQUE constraint failed: entries.token_hash/.test(failure.message)) return error(409);
    return error(503);
  }
  const current=await env.DB.prepare('SELECT revision,status,operation_hash FROM entries WHERE id=?').bind(id).first<Entry>();
  if(current?.revision===revision && current.status===status && current.operation_hash===operationHash) return json({revision,status});
  return error(409);
}
async function publicCode(request:Request,env:Env) {
  const token=bearer(request);
  if(!tokenPattern.test(token)) return error(404);
  const entry=await env.DB.prepare("SELECT id,ciphertext,nonce,key_version FROM entries WHERE token_hash=? AND status='active'").bind(await tokenHash(token)).first<Entry>();
  if(!entry) return error(404);
  if(!entry.ciphertext || !entry.nonce || entry.key_version!==1) return error(503);
  const secret=await decryptSecret({ciphertext:entry.ciphertext,nonce:entry.nonce},env.ENCRYPTION_KEY_B64,entry.id);
  const server_time=Math.floor(Date.now()/1000);
  const valid_until=(Math.floor(server_time/30)+1)*30;
  return json({code:await totp(secret,server_time),remaining_seconds:valid_until-server_time,server_time,valid_until});
}
export default {
  async fetch(request:Request,env:Env):Promise<Response> {
    try {
      const url=new URL(request.url);
      if(url.search) return error(400);
      if(request.method==='GET' && ['/c','/app.js','/style.css'].includes(url.pathname)) {
        const content=url.pathname==='/c' ? html : url.pathname==='/app.js' ? script : css+purchaseCss;
        const type=url.pathname==='/c' ? 'text/html' : url.pathname==='/app.js' ? 'text/javascript' : 'text/css';
        return new Response(content,{headers:{...privacyHeaders,'Content-Type':type+'; charset=utf-8'}});
      }
      if(request.method==='GET' && url.pathname==='/health') return configured(env) ? json({status:'ok'}) : error(503);
      const match=entryPattern.exec(url.pathname);
      const isPublic=url.pathname==='/api/public/code' && request.method==='POST';
      if(!(match && ['PUT','DELETE'].includes(request.method)) && !isPublic) return error(404);
      if(!configured(env)) return error(503);
      // Cloudflare supplies this header; don't accept caller selected forwarding headers.
      const client=request.headers.get('CF-Connecting-IP') ?? 'missing-ip';
      const {success}=await env.REQUEST_LIMITER.limit({key:(isPublic ? 'public:' : 'admin:')+await tokenHash(client)});
      if(!success) return error(429);
      return isPublic ? await publicCode(request,env) : await mutate(request,env,match![1]);
    } catch { return error(503); }
  }
};
