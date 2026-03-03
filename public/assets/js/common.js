function qs(id){ return document.getElementById(id); }

function setMsg(text, ok=false){
  const el = qs('msg');
  if(!el) return;
  el.textContent = text || '';
  el.style.color = ok ? 'rgba(34,197,94,.95)' : 'rgba(255,200,210,.95)';
}

function saveToken(t){ localStorage.setItem('token', t); }
function getToken(){ return localStorage.getItem('token'); }
function clearAuth(){ localStorage.removeItem('token'); }

function getDeviceId(){
  let d = localStorage.getItem('deviceId');
  if(!d){
    d = (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random());
    localStorage.setItem('deviceId', d);
  }
  return d;
}

async function api(path, opts={}){
  const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  const token = getToken();
  if(token) headers.Authorization = 'Bearer ' + token;

  const res = await fetch(path, { ...opts, headers });
  let data = {};
  try { data = await res.json(); } catch { data = { error: 'Bad response' }; }

  if(!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function go(url){ location.href = url; }

async function getLocation(){
  return new Promise((resolve)=>{
    if(!navigator.geolocation) return resolve({});
    navigator.geolocation.getCurrentPosition(
      (pos)=> resolve({
        latitude: pos.coords.latitude,
        longitude: pos.coords.longitude,
        accuracyM: pos.coords.accuracy
      }),
      ()=> resolve({}),
      { enableHighAccuracy:true, timeout:8000 }
    );
  });
}