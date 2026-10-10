import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runInNewContext } from 'node:vm';
import { script } from '../src/page.ts';

function browser(options:{deferred?:boolean;hidden?:boolean}={}) {
  let now=0;
  const elements=Object.fromEntries(['first','last','timer','copy','copy-label'].map(id=>[id,{textContent:'',disabled:true, listeners:new Map<string,Function>(),addEventListener(name:string,handler:Function){this.listeners.set(name,handler);}}]));
  const events=new Map<string,Function>();
  const document={hidden:options.hidden ?? false,getElementById:(id:string)=>elements[id],addEventListener:(name:string,handler:Function)=>events.set(name,handler)};
  const window={addEventListener:(name:string,handler:Function)=>events.set(name,handler)};
  const location={hash:'#AAAAAAAAAAAAAAAAAAAAAA'};
  const requests:Array<{url:string;options:RequestInit}>=[];
  const copied:string[]=[];
  const timers=new Map<number,Function>(); let sequence=0;
  const intervals:Function[]=[];
  let resolveFetch:(response:Response)=>void=()=>{};
  const response=()=>new Response(JSON.stringify({code:'287082',remaining_seconds:1,server_time:59,valid_until:60}));
  runInNewContext(script,{
    document,window,location,AbortController,performance:{now:()=>now},
    navigator:{clipboard:{async writeText(value:string){copied.push(value);}}},
    setTimeout:(handler:Function)=>{const id=++sequence;timers.set(id,handler);return id;},
    clearTimeout:(id:number)=>timers.delete(id),setInterval:(handler:Function)=>intervals.push(handler),
    fetch:(url:string,init:RequestInit)=>{requests.push({url,options:init});return options.deferred ? new Promise<Response>(resolve=>{resolveFetch=resolve;}) : Promise.resolve(response());}
  });
  return {elements,events,document,location,requests,copied,timers,intervals,setNow:(value:number)=>{now=value;},resolve:()=>resolveFetch(response())};
}
const flush=()=>new Promise<void>(resolve=>setImmediate(resolve));
test('public browser sends token only in authorization and copies unformatted valid code',async()=>{
  const b=browser(); await flush();
  assert.equal(b.requests[0].url,'/api/public/code');
  assert.equal((b.requests[0].options.headers as Record<string,string>).Authorization,'Bearer AAAAAAAAAAAAAAAAAAAAAA');
  assert.equal(b.elements.first.textContent,'287'); assert.equal(b.elements.last.textContent,'082');
  assert.equal(b.elements.timer.textContent,'Rotaciona em 1s');
  await b.elements.copy.listeners.get('click')!();
  assert.deepEqual(b.copied,['287082']);
});
test('expired codes immediately clear and cannot be copied even before next interval',async()=>{
  const b=browser(); await flush(); b.setNow(1001);
  await b.elements.copy.listeners.get('click')!();
  assert.deepEqual(b.copied,[]); assert.equal(b.elements.copy.disabled,true);
  assert.equal(b.elements.first.textContent,'•••');
});
test('hidden tab clears code and makes no network request until visible',async()=>{
  const b=browser({hidden:true}); await flush();
  assert.equal(b.requests.length,0);
  b.document.hidden=false; b.events.get('visibilitychange')!(); await flush();
  assert.equal(b.requests.length,1); assert.equal(b.elements.copy.disabled,false);
  b.document.hidden=true; b.events.get('visibilitychange')!();
  assert.equal(b.elements.copy.disabled,true); assert.equal(b.elements.first.textContent,'•••');
});
test('invalid replacement hash invalidates outstanding request to old account',async()=>{
  const b=browser({deferred:true});
  b.location.hash='#invalid'; b.events.get('hashchange')!();
  b.resolve(); await flush();
  assert.equal(b.elements.first.textContent,'•••'); assert.equal(b.elements.copy.disabled,true);
});
