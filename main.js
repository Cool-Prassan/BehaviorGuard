/**
 * BehaviorGuard Desktop — Main Process
 */
'use strict';

const {
  app, BrowserWindow, ipcMain, Tray, Menu,
  nativeImage, Notification, dialog, screen
} = require('electron');
const path   = require('path');
const crypto = require('crypto');
const Store  = require('electron-store');

const store = new Store({ name:'behaviorguard', encryptionKey:'bg-local-store-2024' });

// ── Globals ───────────────────────────────────────────────────
let mainWindow  = null;
let lockWindow  = null;
let setupWindow = null;
let tray        = null;
let uIOhook     = null;
let isMonitoring = false;
let isLocked     = false;

// ── Raw behavioral data ───────────────────────────────────────
const RAW = {
  keydowns: new Map(), ksEvents: [], mouseEvts: [], clicks: [], scrolls: [],
  digraphs: new Map(), trigraphs: new Map(), jitterBuf: [],
  lastRelease: null, nonce: _nonce(), salt: null,
};

// ── Session state ─────────────────────────────────────────────
const SESSION = {
  start: Date.now(), activeTime: 0, lastActive: null, lastTick: Date.now(),
  isTraining: true, phase: 'quick', trainStart: null,
  profile: null, trustScore: null, consecutive: 0, lastCalc: 0,
};

// ── Settings ──────────────────────────────────────────────────
let SETTINGS = store.get('settings', {
  enabled: true, sensitivity: 'medium', privacyMode: true,
  notifications: true, autoBlock: false, autoStart: true, launchAtLogin: false,
});

let ALERTS = store.get('alerts', []);

const QUICK_TARGET = 30  * 60 * 1000;
const FULL_TARGET  = 120 * 60 * 1000;

// ═════════════════════════════════════════════════════════════
// UTILITIES
// ═════════════════════════════════════════════════════════════
function _nonce() { return crypto.randomBytes(16).toString('hex'); }
function _mean(a) { return a.length ? a.reduce((s,x)=>s+x,0)/a.length : 0; }
function _std(a)  { const m=_mean(a); return a.length?Math.sqrt(_mean(a.map(x=>(x-m)**2))):0; }
function _med(a)  { if(!a.length)return 0; const s=[...a].sort((x,y)=>x-y),m=Math.floor(s.length/2); return s.length%2?s[m]:(s[m-1]+s[m])/2; }
function _mad(a)  { const m=_med(a); return _med(a.map(x=>Math.abs(x-m)))*1.4826; }
function _pct(a,p){ if(!a.length)return 0; const s=[...a].sort((x,y)=>x-y); const i=(p/100)*(s.length-1); const lo=Math.floor(i); return s[lo]*(1-(i%1))+(s[Math.ceil(i)]||s[lo])*(i%1); }
function _iqr(a)  { return _pct(a,75)-_pct(a,25); }
function _hashPair(a,b){ return `${a}_${b}`; }

// ═════════════════════════════════════════════════════════════
// PASSWORD HELPERS
// ═════════════════════════════════════════════════════════════
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'bg-salt-2024').digest('hex');
}
function checkPassword(attempt) {
  const stored = store.get('passwordData');
  if (!stored) return false;
  return hashPassword(attempt) === stored.passwordHash;
}
function hasSetup() {
  return !!store.get('passwordData', null);
}

// ═════════════════════════════════════════════════════════════
// ACTIVITY TRACKING
// ═════════════════════════════════════════════════════════════
function markActivity() {
  const now = Date.now();
  if (SESSION.isTraining) {
    if (!SESSION.trainStart) SESSION.trainStart = now;
    if (SESSION.lastActive && (now - SESSION.lastActive) < 10000)
      SESSION.activeTime += (now - SESSION.lastActive);
    SESSION.lastActive = now;
  }
}

// ═════════════════════════════════════════════════════════════
// RAW EVENT HANDLERS
// ═════════════════════════════════════════════════════════════
function onKeyDown(event) {
  if (!isMonitoring || !SETTINGS.enabled) return;
  markActivity();
  const t = Date.now(), kc = event.keycode;
  if (!RAW.keydowns.has(kc)) RAW.keydowns.set(kc, t);
}

function onKeyUp(event) {
  if (!isMonitoring || !SETTINGS.enabled) return;
  markActivity();
  const t = Date.now(), kc = event.keycode, dn = RAW.keydowns.get(kc);
  if (dn === undefined) return;
  RAW.keydowns.delete(kc);
  const dwell = t - dn;
  const flight = RAW.lastRelease ? dn - RAW.lastRelease : null;
  RAW.lastRelease = t;
  if (dwell < 1 || dwell > 1000) return;
  const ev = { kc, dwell, flight, ts: dn, nonce: RAW.nonce };
  RAW.ksEvents.push(ev);
  if (RAW.ksEvents.length > 3000) RAW.ksEvents.shift();
  if (RAW.ksEvents.length >= 2) {
    const prev = RAW.ksEvents[RAW.ksEvents.length - 2];
    const h = _hashPair(prev.kc, kc);
    if (!RAW.digraphs.has(h)) RAW.digraphs.set(h, []);
    const arr = RAW.digraphs.get(h); arr.push(dn - prev.ts);
    if (arr.length > 30) arr.shift();
  }
  if (RAW.ksEvents.length >= 3) {
    const [a, b] = RAW.ksEvents.slice(-3);
    const h = _hashPair(_hashPair(a.kc, b.kc), kc);
    if (!RAW.trigraphs.has(h)) RAW.trigraphs.set(h, []);
    const arr = RAW.trigraphs.get(h); arr.push(dn - a.ts);
    if (arr.length > 30) arr.shift();
  }
}

function onMouseMove(event) {
  if (!isMonitoring || !SETTINGS.enabled) return;
  markActivity();
  const t = Date.now(), ev = { x:event.x, y:event.y, t, nonce:RAW.nonce };
  if (RAW.mouseEvts.length > 0) {
    const p = RAW.mouseEvts[RAW.mouseEvts.length - 1], dt = (t - p.t) / 1000;
    if (dt > 0 && dt < 0.5) {
      const dx = event.x - p.x, dy = event.y - p.y;
      ev.v = Math.sqrt(dx*dx + dy*dy) / dt;
      if (p.v !== undefined) {
        const acc = Math.abs(ev.v - p.v) / dt;
        ev.acc = acc;
        RAW.jitterBuf.push({ t, acc, v: ev.v });
        if (RAW.jitterBuf.length > 200) RAW.jitterBuf.shift();
      }
    }
  }
  RAW.mouseEvts.push(ev);
  if (RAW.mouseEvts.length > 2000) RAW.mouseEvts.shift();
}

function onClick(event) {
  if (!isMonitoring || !SETTINGS.enabled) return;
  markActivity();
  RAW.clicks.push({ x:event.x, y:event.y, t:Date.now(), btn:event.button, nonce:RAW.nonce });
  if (RAW.clicks.length > 500) RAW.clicks.shift();
}

function onWheel(event) {
  if (!isMonitoring || !SETTINGS.enabled) return;
  markActivity();
  RAW.scrolls.push({ amount:event.rotation, t:Date.now() });
  if (RAW.scrolls.length > 300) RAW.scrolls.shift();
}

// ═════════════════════════════════════════════════════════════
// FEATURE EXTRACTION
// ═════════════════════════════════════════════════════════════
function extractKS() {
  const v = RAW.ksEvents.filter(k => k.dwell && k.dwell < 1000);
  if (v.length < 50) return null;
  const dw = v.map(k=>k.dwell);
  const fl = v.filter(k=>k.flight&&k.flight>0&&k.flight<2000).map(k=>k.flight);
  const iv = [];
  for (let i=1;i<v.length;i++){const d=v[i].ts-v[i-1].ts;if(d>0&&d<2000)iv.push(d);}
  const digVars = [];
  for (const [,t] of RAW.digraphs) { if(t.length>=3) digVars.push(_std(t)); }
  return {
    medDwell:_med(dw), madDwell:_mad(dw), p25Dwell:_pct(dw,25), p75Dwell:_pct(dw,75), iqrDwell:_iqr(dw),
    avgDwell:_mean(dw), stdDwell:_std(dw),
    medFlight:fl.length?_med(fl):0, madFlight:fl.length?_mad(fl):0,
    medIv:iv.length?_med(iv):0, madIv:iv.length?_mad(iv):0, iqrIv:iv.length?_iqr(iv):0,
    wpm:(()=>{if(v.length<10)return 0;const dur=(v[v.length-1].ts-v[0].ts)/60000;return dur>0?(v.length/5)/dur:0})(),
    digVar:digVars.length?_med(digVars):0, n:v.length
  };
}

function extractMouse() {
  const m = RAW.mouseEvts;
  if (m.length < 30) return null;
  const vels=[], angles=[];
  for (let i=1;i<m.length;i++){
    const a=m[i-1],b=m[i],dt=(b.t-a.t)/1000;
    if(dt>0&&dt<0.5){
      const dx=b.x-a.x,dy=b.y-a.y;
      vels.push(Math.sqrt(dx*dx+dy*dy)/dt);
      if(i>1) angles.push(Math.abs(Math.atan2(dy,dx)-Math.atan2(a.y-m[i-2].y,a.x-m[i-2].x)));
    }
  }
  const entropy=(()=>{
    if(angles.length<10)return 0;
    const bins=new Array(10).fill(0),bs=Math.PI/10;
    angles.forEach(x=>bins[Math.min(9,Math.floor(x/bs))]++);
    let e=0;bins.forEach(c=>{if(c>0){const p=c/angles.length;e-=p*Math.log2(p);}});
    return Math.min(1,Math.abs(e)/3.32);
  })();
  let jFreq=0,jAmp=0;
  if(RAW.jitterBuf.length>=20){
    const acc=RAW.jitterBuf.map(j=>j.acc).filter(x=>x!==undefined);
    if(acc.length>=10){
      const m2=_mean(acc);let zc=0;
      for(let i=1;i<acc.length;i++)if((acc[i]-m2)*(acc[i-1]-m2)<0)zc++;
      const dur=(RAW.jitterBuf[RAW.jitterBuf.length-1].t-RAW.jitterBuf[0].t)/1000;
      jFreq=dur>0?(zc/2)/dur:0; jAmp=_std(acc);
    }
  }
  return {avgVel:_mean(vels),stdVel:_std(vels),curvature:angles.length?_mean(angles)/Math.PI:0,entropy,jitterFreq:jFreq,jitterAmp:jAmp,n:m.length};
}

function extractClick() {
  const c = RAW.clicks;
  if (c.length < 5) return null;
  const ivs=[],dists=[];
  for(let i=1;i<c.length;i++){
    ivs.push(c[i].t-c[i-1].t);
    const dx=c[i].x-c[i-1].x,dy=c[i].y-c[i-1].y;
    dists.push(Math.sqrt(dx*dx+dy*dy));
  }
  const dur=(c[c.length-1].t-c[0].t)/60000;
  return {avgIv:_mean(ivs),stdIv:_std(ivs),avgDist:_mean(dists),cpm:dur>0?c.length/dur:0,n:c.length};
}

// ═════════════════════════════════════════════════════════════
// BOT + REPLAY DETECTION
// ═════════════════════════════════════════════════════════════
function detectBot(ks, mouse) {
  let score=0; const reasons=[];
  if(mouse){
    if(mouse.entropy<0.02){score+=40;reasons.push('Mouse entropy < 0.02');}
    const human=mouse.jitterFreq>=3&&mouse.jitterFreq<=12;
    if(!human&&mouse.jitterFreq>0){score+=30;reasons.push(`Jitter ${mouse.jitterFreq.toFixed(1)}Hz`);}
    if(mouse.curvature<0.01){score+=25;reasons.push('Perfect geometric paths');}
  }
  if(ks){
    if(ks.medIv<30){score+=50;reasons.push('Superhuman speed <30ms');}
    const cv=ks.medIv>0?ks.iqrIv/ks.medIv:0;
    if(cv<0.15&&ks.n>30){score+=25;reasons.push(`CV=${cv.toFixed(3)} too consistent`);}
    if(ks.digVar<3&&RAW.digraphs.size>10){score+=20;reasons.push('Digraph variance too low');}
  }
  if(RAW.mouseEvts.length>=20){
    const r=RAW.mouseEvts.slice(-50);let changes=0;
    for(let i=2;i<r.length;i++){
      const a1=Math.atan2(r[i-1].y-r[i-2].y,r[i-1].x-r[i-2].x);
      const a2=Math.atan2(r[i].y-r[i-1].y,r[i].x-r[i-1].x);
      if(Math.abs(a1-a2)>0.1&&Math.abs(a1-a2)<Math.PI-0.1)changes++;
    }
    if((changes/(r.length-2))<0.15){score+=30;reasons.push('No micro-corrections');}
  }
  return {isBot:score>=85,confidence:Math.min(100,score),reason:reasons.join('; ')};
}

function detectReplay() {
  const recent=RAW.ksEvents.slice(-20);
  const nonces=new Set(recent.map(k=>k.nonce).filter(Boolean));
  if(nonces.size>1)return{isReplay:true,reason:'Multiple session nonces'};
  const ivs=[];
  for(let i=1;i<recent.length;i++)ivs.push(recent[i].ts-recent[i-1].ts);
  if(ivs.length>5&&new Set(ivs).size===1)return{isReplay:true,reason:'Identical intervals'};
  return{isReplay:false};
}

// ═════════════════════════════════════════════════════════════
// RISK CALCULATION
// ═════════════════════════════════════════════════════════════
function calcTrustScore() {
  if(!SESSION.profile||!SESSION.profile.features)return null;
  const cur={ks:extractKS(),mouse:extractMouse(),click:extractClick()};
  if(!cur.ks&&!cur.mouse)return SESSION.trustScore;
  const base=SESSION.profile.features, parts=[];
  if(cur.ks&&base.ks){
    let d=0,n=0;
    const cmp=(cv,bv,tol=0.6)=>{if(bv>0){d+=Math.min(1,Math.abs(cv-bv)/bv/tol)*100;n++;}};
    cmp(cur.ks.medDwell,base.ks.medDwell,0.6); cmp(cur.ks.madDwell,base.ks.madDwell,0.7);
    cmp(cur.ks.medFlight,base.ks.medFlight,0.7); cmp(cur.ks.medIv,base.ks.medIv,0.65);
    cmp(cur.ks.wpm,base.ks.wpm,0.6);
    parts.push({r:n?d/n:0,w:0.5});
  }
  if(cur.mouse&&base.mouse){
    let d=0,n=0;
    if(base.mouse.avgVel>0){d+=Math.min(1,Math.abs(cur.mouse.avgVel-base.mouse.avgVel)/base.mouse.avgVel)*100;n++;}
    d+=Math.min(1,Math.abs(cur.mouse.curvature-base.mouse.curvature))*100;n++;
    d+=Math.min(1,Math.abs(cur.mouse.entropy-base.mouse.entropy))*100;n++;
    parts.push({r:n?d/n:0,w:0.3});
  }
  if(cur.click&&base.click){
    let d=0,n=0;
    if(base.click.cpm>0){d+=Math.min(1,Math.abs(cur.click.cpm-base.click.cpm)/base.click.cpm/1.2)*100;n++;}
    if(base.click.avgDist>0){d+=Math.min(1,Math.abs(cur.click.avgDist-base.click.avgDist)/base.click.avgDist/1.2)*100;n++;}
    parts.push({r:n?d/n:0,w:0.2});
  }
  if(!parts.length)return SESSION.trustScore;
  const tw=parts.reduce((s,x)=>s+x.w,0);
  const risk=parts.reduce((s,x)=>s+x.r*x.w,0)/tw;
  const h=new Date().getHours(),day=new Date().getDay();
  let adj=1.0;
  if(h<5||h>=22)adj*=0.85; if(day===0||day===6)adj*=0.90; if(h>=5&&h<12)adj*=0.92;
  return Math.max(0,Math.min(100,100-risk*adj));
}

// ═════════════════════════════════════════════════════════════
// ANALYSIS LOOP
// ═════════════════════════════════════════════════════════════
let analysisTimer=null;
function startAnalysisLoop(){analysisTimer=setInterval(tick,3000);}
function stopAnalysisLoop(){if(analysisTimer){clearInterval(analysisTimer);analysisTimer=null;}}

function tick() {
  if(!isMonitoring)return;
  const now=Date.now();
  if(SESSION.isTraining&&SESSION.lastActive&&(now-SESSION.lastActive)<10000)
    SESSION.activeTime+=(now-SESSION.lastTick);
  SESSION.lastTick=now;
  if(SESSION.isTraining){checkTrainingProgress();pushStats();return;}
  const score=calcTrustScore();
  if(score!==null){
    SESSION.trustScore=score;
    const ks=extractKS(),mouse=extractMouse(),click=extractClick();
    const bot=detectBot(ks,mouse);
    const replay=detectReplay();
    if(bot.isBot){const a=addAlert({type:'bot',severity:'critical',msg:`Bot activity: ${bot.reason}`});sendToRenderer('alert',a);}
    if(replay.isReplay){const a=addAlert({type:'replay',severity:'high',msg:`Replay attack: ${replay.reason}`});sendToRenderer('alert',a);}
    const thr={low:15,medium:30,high:50}[SETTINGS.sensitivity]||30;
    if(score<thr){
      SESSION.consecutive++;
      if(SESSION.consecutive>=3){
        const a=addAlert({type:'anomaly',severity:score<20?'critical':'high',msg:`Trust score at ${Math.round(score)}% for 3+ cycles`});
        sendToRenderer('alert',a);
        if(SETTINGS.autoBlock&&score<20&&!isLocked)showLockScreen();
        SESSION.consecutive=0;
      }
    } else {SESSION.consecutive=0;}
    updateTray();
    sendToRenderer('risk-update',{trustScore:score,botScore:bot.confidence,ksFeats:ks,mouseFeats:mouse,clickFeats:click});
  }
  pushStats();
}

function pushStats(){sendToRenderer('stats-update',buildStatsPayload());}

function buildStatsPayload(){
  const target=SESSION.phase==='quick'?QUICK_TARGET:FULL_TARGET;
  const pct=SESSION.isTraining?Math.min(100,(SESSION.activeTime/target)*100):100;
  return {
    ks:RAW.ksEvents.length, mouse:RAW.mouseEvts.length, clicks:RAW.clicks.length, digs:RAW.digraphs.size,
    isTraining:SESSION.isTraining, phase:SESSION.phase, activeTime:Math.floor(SESSION.activeTime/1000),
    trainPct:Math.round(pct), trustScore:SESSION.trustScore, hasProfile:!!SESSION.profile,
    sessionStart:SESSION.start, isMonitoring,
  };
}

// ═════════════════════════════════════════════════════════════
// TRAINING
// ═════════════════════════════════════════════════════════════
function checkTrainingProgress(){
  const target=SESSION.phase==='quick'?QUICK_TARGET:FULL_TARGET;
  const pct=Math.min(100,(SESSION.activeTime/target)*100);
  if(pct>=100){
    if(SESSION.phase==='quick'){
      SESSION.phase='intermediate'; SESSION.activeTime=0; SESSION.lastActive=Date.now();
      notify('Quick training complete!','Full training has started. Keep using your computer.');
      sendToRenderer('training-phase',{phase:'intermediate'});
    } else {completeTraining();}
  }
}

function completeTraining(){
  const ks=extractKS(),mouse=extractMouse(),click=extractClick();
  if(!ks&&!mouse)return;
  SESSION.profile={
    uid:'user_'+crypto.randomBytes(6).toString('hex'), createdAt:Date.now(),
    features:{ks,mouse,click},
    digraphs:Object.fromEntries(RAW.digraphs), trigraphs:Object.fromEntries(RAW.trigraphs),
    size:{keystrokes:RAW.ksEvents.length,mouse:RAW.mouseEvts.length,clicks:RAW.clicks.length,digraphs:RAW.digraphs.size},
    v:'3.0'
  };
  SESSION.isTraining=false; SESSION.phase='complete';
  store.set('profile',SESSION.profile); store.delete('training');
  notify('Training complete!','BehaviorGuard is now actively protecting you.');
  sendToRenderer('training-complete',{size:SESSION.profile.size,createdAt:SESSION.profile.createdAt});
  updateTray();
}

// ═════════════════════════════════════════════════════════════
// STORAGE
// ═════════════════════════════════════════════════════════════
function loadProfile(){
  const p=store.get('profile');
  if(p){
    SESSION.profile=p; SESSION.isTraining=false; SESSION.phase='complete';
    if(p.digraphs)RAW.digraphs=new Map(Object.entries(p.digraphs));
    if(p.trigraphs)RAW.trigraphs=new Map(Object.entries(p.trigraphs));
  }
  const tr=store.get('training');
  if(tr&&SESSION.isTraining){
    SESSION.activeTime=tr.activeTime||0; SESSION.phase=tr.phase||'quick';
    if(tr.ksEvents)RAW.ksEvents=tr.ksEvents;
    if(tr.digs)RAW.digraphs=new Map(Object.entries(tr.digs));
    SESSION.lastActive=Date.now();
  }
}

function saveTrainingProgress(){
  if(!SESSION.isTraining)return;
  store.set('training',{ksEvents:RAW.ksEvents.slice(-500),activeTime:SESSION.activeTime,phase:SESSION.phase,digs:Object.fromEntries(RAW.digraphs),saved:Date.now()});
}

function resetProfile(){
  SESSION.profile=null; SESSION.isTraining=true; SESSION.phase='quick';
  SESSION.activeTime=0; SESSION.lastActive=null; SESSION.trustScore=null;
  SESSION.consecutive=0; SESSION.trainStart=null;
  RAW.ksEvents=[]; RAW.mouseEvts=[]; RAW.clicks=[]; RAW.scrolls=[];
  RAW.digraphs.clear(); RAW.trigraphs.clear(); RAW.jitterBuf=[];
  RAW.lastRelease=null; RAW.nonce=_nonce();
  ALERTS=[]; store.delete('profile'); store.delete('training'); store.set('alerts',[]);
  sendToRenderer('profile-reset',{}); updateTray();
}

// ═════════════════════════════════════════════════════════════
// ALERTS
// ═════════════════════════════════════════════════════════════
function addAlert(a){
  const alert={...a,ts:Date.now(),id:Date.now()+Math.random()};
  ALERTS.unshift(alert); if(ALERTS.length>200)ALERTS.pop();
  store.set('alerts',ALERTS.slice(0,100));
  if(SETTINGS.notifications)notify('BehaviorGuard Alert',a.msg);
  return alert;
}

// ═════════════════════════════════════════════════════════════
// LOCK SCREEN
// ═════════════════════════════════════════════════════════════
function showLockScreen(){
  if(isLocked||lockWindow)return;
  isLocked=true;
  const{width,height}=screen.getPrimaryDisplay().workAreaSize;
  lockWindow=new BrowserWindow({
    width,height,frame:false,alwaysOnTop:true,resizable:false,fullscreen:true,skipTaskbar:false,
    webPreferences:{nodeIntegration:false,contextIsolation:true,preload:path.join(__dirname,'preload.js')}
  });
  lockWindow.loadFile('lock.html',{hash:`score=${Math.round(SESSION.trustScore||0)}`});
  lockWindow.setVisibleOnAllWorkspaces(true,{visibleOnFullScreen:true});
  lockWindow.on('closed',()=>{lockWindow=null;isLocked=false;});
}

function unlockScreen(){
  if(lockWindow)lockWindow.close();
  isLocked=false;
}

// ═════════════════════════════════════════════════════════════
// TRAY
// ═════════════════════════════════════════════════════════════
function createTray(){
  let icon;
  try{
    icon=nativeImage.createFromPath(path.join(__dirname,'assets','icon.png'));
    if(icon.isEmpty())throw new Error('empty');
  }catch{
    icon=nativeImage.createFromDataURL('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAdgAAAHYBTnsmCAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAABUSURBVDiNY2AY/P+fgQEABv4B/gAAAABJRU5ErkJggg==');
  }
  tray=new Tray(icon.resize({width:16,height:16}));
  tray.setToolTip('BehaviorGuard');
  updateTray();
  tray.on('click',()=>{if(mainWindow){mainWindow.isVisible()?mainWindow.hide():mainWindow.show();}});
}

function updateTray(){
  if(!tray)return;
  const score=SESSION.trustScore;
  const label=score===null?'Training…':score>=70?`Verified ${Math.round(score)}%`:score>=40?`Uncertain ${Math.round(score)}%`:`Suspicious ${Math.round(score)}%`;
  tray.setToolTip(`BehaviorGuard — ${label}`);
  const menu=Menu.buildFromTemplate([
    {label:`BehaviorGuard — ${label}`,enabled:false},
    {label:isMonitoring?'Monitoring active':'Monitoring paused',enabled:false},
    {type:'separator'},
    {label:'Show Dashboard',click:()=>{mainWindow?.show();}},
    {label:isMonitoring?'Pause Monitoring':'Resume Monitoring',click:toggleMonitoring},
    {type:'separator'},
    {label:'Alerts',click:()=>{mainWindow?.show();sendToRenderer('navigate','alerts');}},
    {label:'Settings',click:()=>{mainWindow?.show();sendToRenderer('navigate','settings');}},
    {type:'separator'},
    {label:'Quit',click:()=>{app.isQuiting=true;app.quit();}},
  ]);
  tray.setContextMenu(menu);
}

// ═════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═════════════════════════════════════════════════════════════
function notify(title,body){
  if(!SETTINGS.notifications||!Notification.isSupported())return;
  new Notification({title,body}).show();
}

// ═════════════════════════════════════════════════════════════
// MONITORING
// ═════════════════════════════════════════════════════════════
function startMonitoring(){
  if(isMonitoring)return;
  try{
    const{uIOhook:hook}=require('uiohook-napi');
    uIOhook=hook;
    hook.on('keydown',onKeyDown); hook.on('keyup',onKeyUp);
    hook.on('mousemove',onMouseMove); hook.on('click',onClick); hook.on('wheel',onWheel);
    hook.start();
    isMonitoring=true;
    startAnalysisLoop();
    sendToRenderer('monitoring-status',true);
    updateTray();
    setInterval(saveTrainingProgress,30000);
  }catch(err){
    console.error('[BG] uiohook failed:',err.message);
    isMonitoring=false;
    dialog.showMessageBox({type:'warning',title:'Permission Required',message:'BehaviorGuard needs Accessibility permission.',detail:'Windows: Run as Administrator.\nmacOS: System Settings → Privacy → Accessibility → enable BehaviorGuard.',buttons:['OK']});
  }
}

function stopMonitoring(){
  if(!isMonitoring)return;
  isMonitoring=false;
  if(uIOhook){try{uIOhook.stop();}catch{}}
  stopAnalysisLoop(); saveTrainingProgress();
  sendToRenderer('monitoring-status',false); updateTray();
}

function toggleMonitoring(){isMonitoring?stopMonitoring():startMonitoring();}

function sendToRenderer(channel,data){
  if(mainWindow&&!mainWindow.isDestroyed())mainWindow.webContents.send(channel,data);
}

// ═════════════════════════════════════════════════════════════
// IPC HANDLERS
// ═════════════════════════════════════════════════════════════
ipcMain.handle('get-stats',    ()=>buildStatsPayload());
ipcMain.handle('get-alerts',   ()=>ALERTS);
ipcMain.handle('clear-alerts', ()=>{ALERTS=[];store.set('alerts',[]);return true;});
ipcMain.handle('get-settings', ()=>SETTINGS);
ipcMain.handle('save-settings',(_, s)=>{
  SETTINGS={...SETTINGS,...s};
  store.set('settings',SETTINGS);
  app.setLoginItemSettings({openAtLogin:!!SETTINGS.launchAtLogin});
  return true;
});
ipcMain.handle('start-monitoring',()=>{startMonitoring();return isMonitoring;});
ipcMain.handle('stop-monitoring', ()=>{stopMonitoring(); return isMonitoring;});
ipcMain.handle('toggle-monitoring',()=>{toggleMonitoring();return isMonitoring;});
ipcMain.handle('reset-profile',()=>{resetProfile();return true;});
ipcMain.handle('export-profile',async()=>{
  if(!SESSION.profile)throw new Error('No profile');
  const{filePath}=await dialog.showSaveDialog({defaultPath:`bg_profile_${Date.now()}.json`,filters:[{name:'JSON',extensions:['json']}]});
  if(!filePath)return false;
  require('fs').writeFileSync(filePath,JSON.stringify(SESSION.profile,null,2));
  return true;
});
ipcMain.handle('import-profile',async()=>{
  const{filePaths}=await dialog.showOpenDialog({filters:[{name:'JSON',extensions:['json']}],properties:['openFile']});
  if(!filePaths.length)return false;
  const raw=JSON.parse(require('fs').readFileSync(filePaths[0],'utf8'));
  SESSION.profile=raw; SESSION.isTraining=false;
  store.set('profile',raw); sendToRenderer('profile-loaded',raw);
  return true;
});
ipcMain.handle('unlock',()=>unlockScreen());
ipcMain.handle('win-minimize',()=>mainWindow?.minimize());
ipcMain.handle('win-maximize',()=>mainWindow?.isMaximized()?mainWindow?.unmaximize():mainWindow?.maximize());
ipcMain.handle('win-hide',    ()=>mainWindow?.hide());
ipcMain.handle('get-version', ()=>app.getVersion());

// ── Password & Setup IPC ──────────────────────────────────────
ipcMain.handle('has-setup',        ()=>hasSetup());
ipcMain.handle('get-password-data',()=>store.get('passwordData',null));
ipcMain.handle('check-password',   (_,attempt)=>checkPassword(attempt));
ipcMain.handle('save-password',    (_,data)=>{
  store.set('passwordData',{passwordHash:hashPassword(data.password),recovery:data.recovery,createdAt:Date.now()});
  return true;
});
ipcMain.handle('reset-password',(_,newPw)=>{
  const existing=store.get('passwordData',{});
  store.set('passwordData',{...existing,passwordHash:hashPassword(newPw),updatedAt:Date.now()});
  return true;
});
ipcMain.handle('finish-setup',()=>{
  store.set('setupComplete',true);
  // Close setup, open main dashboard
  if(setupWindow){setupWindow.close();setupWindow=null;}
  createMainWindow();
  setTimeout(()=>{
    loadProfile();
    sendToRenderer('stats-update',buildStatsPayload());
    if(SETTINGS.enabled){
      try{startMonitoring();}catch(e){console.error('Monitoring error:',e);}
    }
  },800);
  return true;
});

// ═════════════════════════════════════════════════════════════
// WINDOWS
// ═════════════════════════════════════════════════════════════
function createSetupWindow(){
  setupWindow=new BrowserWindow({
    width:480, height:680, frame:false, resizable:false,
    backgroundColor:'#0a0c12',
    webPreferences:{nodeIntegration:false,contextIsolation:true,preload:path.join(__dirname,'preload.js')},
  });
  setupWindow.loadFile('setup.html');
  // Apply CSP
  setupWindow.webContents.session.webRequest.onHeadersReceived((details,callback)=>{
    callback({responseHeaders:{...details.responseHeaders,'Content-Security-Policy':["default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com data:"]}});
  });
  setupWindow.on('closed',()=>{setupWindow=null;});
}

function createMainWindow(){
  mainWindow=new BrowserWindow({
    width:1300, height:860, minWidth:1100, minHeight:680,
    frame:false, transparent:false, backgroundColor:'#07090f',
    webPreferences:{nodeIntegration:false,contextIsolation:true,preload:path.join(__dirname,'preload.js')},
    icon:path.join(__dirname,'assets','icon.png'),
    show:false,
  });
  mainWindow.loadFile('behaviorguard.html');
  // Apply CSP
  mainWindow.webContents.session.webRequest.onHeadersReceived((details,callback)=>{
    callback({responseHeaders:{...details.responseHeaders,'Content-Security-Policy':["default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com data:"]}});
  });
  mainWindow.once('ready-to-show',()=>{
    mainWindow.show();
    setTimeout(()=>{
      sendToRenderer('stats-update',buildStatsPayload());
      if(SESSION.profile)sendToRenderer('profile-loaded',{size:SESSION.profile.size,createdAt:SESSION.profile.createdAt});
    },600);
  });
  mainWindow.on('close',(e)=>{
    if(!app.isQuiting){
      e.preventDefault(); mainWindow.hide();
      if(Notification.isSupported())new Notification({title:'BehaviorGuard',body:'Still monitoring in the background.'}).show();
    }
  });
  mainWindow.on('closed',()=>{mainWindow=null;});
}

// ═════════════════════════════════════════════════════════════
// APP LIFECYCLE
// ═════════════════════════════════════════════════════════════
app.whenReady().then(()=>{
  createTray();

  if(!hasSetup()){
    // First run — show setup wizard only
    createSetupWindow();
  } else {
    // Returning user — go straight to dashboard
    createMainWindow();
    loadProfile();
    if(SETTINGS.enabled){
      setTimeout(()=>{
        try{startMonitoring();}
        catch(e){console.error('Monitoring failed:',e);}
      },2000);
    }
  }

  app.on('activate',()=>{
    if(!mainWindow&&!setupWindow) createMainWindow();
    else if(mainWindow) mainWindow.show();
  });
});

app.on('window-all-closed',()=>{
  // Stay alive in tray — don't quit
});

app.on('before-quit',()=>{
  app.isQuiting=true;
  saveTrainingProgress();
  stopMonitoring();
});

process.on('uncaughtException',err=>{console.error('[BG] Uncaught:',err);});