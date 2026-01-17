// web/script.js

// Truncate long values for UI
function clip(text, max = 256) {
  if (!text) return '';
  return text.length > max
    ? (text.slice(0, max) + `… (${text.length} chars)`)
    : text;
}

function makeUrl(path) {
  return path; // relative to same origin
}

async function api(path, method = "GET", body = null) {
  const token = localStorage.getItem('token');
  const url = new URL(path, window.location.origin);

  if (token) url.searchParams.set("token", token);

  const headers = {};
  const fetchOpts = { method, headers };

  if (body !== null) {
    headers["Content-Type"] = "application/json";
    fetchOpts.body = JSON.stringify(body);
  }

  const res = await fetch(url, fetchOpts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function apiForm(path, formData) {
  const token = localStorage.getItem('token');
  const url = new URL(path, window.location.origin);

  if (token) url.searchParams.set("token", token);

  const res = await fetch(url, { method: "POST", body: formData });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function ensureAuth(expectedRole){
  const token = localStorage.getItem('token');
  const role  = localStorage.getItem('role');

  if (!token || !role || (expectedRole && role !== expectedRole)) {
    alert("Please login");
    location.href = 'login.html';
  }
}

async function loadStudents(){
  const res = await api('/users/students');
  const sel = document.getElementById('students');
  if(sel){
    sel.innerHTML = '';
    res.forEach(s=>{
      const opt = document.createElement('option');
      opt.value = s.id;
      opt.textContent = `${s.name} <${s.email}>`;
      sel.appendChild(opt);
    });
  }
}

function logout(){
  localStorage.clear();
  location.href = "/";
}


function prettyTime(ts) {
  if (!ts) return '';

  // Normalize UTC (fix timestamps missing 'Z')
  const iso = ts.endsWith('Z') ? ts : ts + 'Z';
  const d = new Date(iso);

  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

