export const html=`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>Autenticação 2FA</title><link rel="stylesheet" href="/style.css"><script src="/app.js" defer></script></head>
<body><div class="page"><section class="purchase-notice" aria-label="Agradecimento pela compra"><p class="purchase-title">✅ OBRIGADO PELA COMPRA!</p><p class="purchase-message">Deixa uma avaliação para dar uma moral? :)</p></section><main class="card" aria-labelledby="heading"><header><div class="title"><svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z"/><path d="m8 12 3 3 5-6"/></svg><h1 id="heading">Autenticação 2FA</h1></div><p id="timer" class="timer" role="status" aria-live="polite">Carregando código…</p></header><div class="code-row"><div><p class="code-label">Código atual</p><div id="code" class="code" aria-label="Código de autenticação"><span id="first">•••</span><span id="last">•••</span></div></div><button id="copy" type="button" disabled><svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg><span id="copy-label">Copiar código</span></button></div><p class="note">O código muda a cada 30 segundos.</p></main></div></body></html>`;
export const css=`:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#09090b;color:#fafafa}*{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;padding:16px}.card{width:100%;max-width:684px;min-height:185px;padding:14px;border:1px solid #44216a;border-radius:6px;background:#151021}header{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:18px;color:#c4a8f5}.title{display:flex;align-items:center;gap:7px;flex-shrink:0}h1{font-size:13px;font-weight:600;line-height:18px;margin:0}.timer{color:#a1a1aa;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:9px;line-height:15px;text-align:right;margin:0}.code-row{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-top:14px;border:1px solid #27272a;border-radius:8px;background:#121215;padding:12px 13px;min-height:78px}.code-label{color:#81818c;font-size:10px;letter-spacing:1.5px;line-height:14px;text-transform:uppercase;margin:0 0 5px}.code{display:flex;gap:18px;white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:22px;font-weight:700;letter-spacing:3.5px;line-height:27px;font-variant-numeric:tabular-nums}.note{color:#a1a1aa;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:9px;line-height:15px;margin:20px 0 2px}button{display:flex;align-items:center;justify-content:center;gap:9px;flex-shrink:0;border:1px solid #604780;background:#2a2239;color:#e6dcf7;border-radius:9px;height:40px;padding:0 13px;font:inherit;font-size:13px;font-weight:600;cursor:pointer;transition:background .15s}button:hover:enabled{background:#352b48}button:focus-visible{outline:2px solid #c4a5fa;outline-offset:3px}button:disabled{opacity:.5;cursor:default}@media(max-width:390px){.card{padding:12px}.code-row{padding:12px 10px;gap:10px}.code{font-size:20px;letter-spacing:2px;gap:12px}button{font-size:11px;padding:0 8px;gap:6px}header{gap:8px}.timer{font-size:8px}}@media(max-width:310px){.code-row{align-items:stretch;flex-direction:column}.timer{max-width:80px}.card{min-height:auto}}`;
export const purchaseCss=`.page{width:100%;max-width:684px;display:grid;gap:16px}.purchase-notice{padding:22px 18px;border:1px solid #2c6951;border-radius:8px;background:#0e2019;text-align:center;box-shadow:inset 0 3px 0 #5eead4}.purchase-title{margin:0;color:#99f6c5;font-size:clamp(17px,4.5vw,24px);font-weight:800;line-height:1.35;letter-spacing:.3px;text-wrap:balance}.purchase-message{margin:9px 0 0;color:#e4f5ec;font-size:clamp(12px,3.5vw,15px);line-height:1.6;text-wrap:balance}@media(max-width:390px){.page{gap:12px}.purchase-notice{padding:18px 12px}}`;
export const script=`'use strict';
(() => {
  let token=location.hash.slice(1);
  let code='', expires=0, timer, requestId=0, controller, loading=false;
  const first=document.getElementById('first'), last=document.getElementById('last'),
    status=document.getElementById('timer'), button=document.getElementById('copy'), label=document.getElementById('copy-label');
  function clear(message) { code=''; expires=0; first.textContent='•••'; last.textContent='•••'; button.disabled=true; status.textContent=message; label.textContent='Copiar código'; }
  function tick() {
    const remaining=Math.max(0,Math.ceil((expires-performance.now())/1000));
    if(!remaining) { if(code) clear('Atualizando código…'); if(!loading && !document.hidden) load(); return; }
    status.textContent='Rotaciona em '+remaining+'s';
  }
  async function load() {
    clearTimeout(timer);
    const current=++requestId; if(controller) controller.abort(); loading=false;
    if(document.hidden) { clear('Atualizando código…'); return; }
    if(!/^[A-Za-z0-9_-]{21}[AQgw]$/.test(token)) { clear('Link inválido ou indisponível.'); return; }
    controller=new AbortController(); const activeController=controller;
    const timeout=setTimeout(()=>activeController.abort(),8000), started=performance.now(); loading=true;
    try {
      const response=await fetch('/api/public/code',{method:'POST',headers:{Authorization:'Bearer '+token},cache:'no-store',credentials:'omit',signal:controller.signal});
      if(!response.ok) throw new Error('unavailable');
      const data=await response.json();
      if(current!==requestId || document.hidden) return;
      if(!/^\\d{6}$/.test(data.code) || !Number.isInteger(data.remaining_seconds) || data.remaining_seconds<1 || data.remaining_seconds>30 || !Number.isInteger(data.server_time) || data.valid_until!==data.server_time+data.remaining_seconds) throw new Error('invalid');
      expires=started+data.remaining_seconds*1000;
      if(expires<=performance.now()) throw new Error('expired');
      code=data.code; first.textContent=code.slice(0,3); last.textContent=code.slice(3); button.disabled=false; label.textContent='Copiar código'; tick();
    } catch { if(current===requestId) clear('Código indisponível. Tentando novamente…'); }
    finally { clearTimeout(timeout); if(current===requestId) { loading=false; timer=setTimeout(load,code ? Math.max(100,expires-performance.now()) : 5000); } }
  }
  button.addEventListener('click',async()=> {
    if(!code || expires<=performance.now()) { clear('Atualizando código…'); load(); return; }
    try { await navigator.clipboard.writeText(code); label.textContent='Código copiado'; }
    catch { label.textContent='Não foi possível copiar'; }
  });
  document.addEventListener('visibilitychange',()=> {
    if(document.hidden) { ++requestId; loading=false; clearTimeout(timer); if(controller) controller.abort(); clear('Atualizando código…'); }
    else load();
  });
  window.addEventListener('hashchange',()=>{ token=location.hash.slice(1); clear('Carregando código…'); load(); });
  window.addEventListener('pagehide',()=>{ ++requestId; clearTimeout(timer); if(controller) controller.abort(); clear('Atualizando código…'); });
  window.addEventListener('pageshow',event=>{ if(event.persisted) load(); });
  setInterval(()=>{ if(code) tick(); },200); load();
})();`;
