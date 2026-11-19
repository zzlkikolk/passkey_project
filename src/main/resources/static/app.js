const $ = (id) => document.getElementById(id);
const status = (text, type = 'idle') => { $('status').textContent = text; $('status').className = `status ${type}`; };
const encode = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const decode = (value) => { const normalized = value.replace(/-/g, '+').replace(/_/g, '/'); const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4); return Uint8Array.from(atob(padded), c => c.charCodeAt(0)); };
const call = async (url, body) => { const response = await fetch(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) }); const json = await response.json(); if (!response.ok) throw new Error(json.error || '请求失败'); return json; };
const setBusy = (busy) => { $('register').disabled = busy; $('login').disabled = busy; };

async function register() {
  const username = $('username').value.trim();
  const displayName = $('displayName').value.trim() || username;
  if (!username) return status('请先输入用户名', 'error');
  if (!window.PublicKeyCredential) return status('当前浏览器不支持 WebAuthn', 'error');
  setBusy(true); status('正在向设备请求注册凭据…', 'loading');
  try {
    const options = await call('/api/auth/register/options', {username, displayName});
    const publicKey = {...options, challenge: decode(options.challenge), user: {...options.user, id: decode(options.user.id)}};
    const credential = await navigator.credentials.create({publicKey});
    const response = credential.response;
    await call('/api/auth/register/verify', { username, credentialId: encode(credential.rawId), clientDataJSON: encode(response.clientDataJSON), attestationObject: encode(response.attestationObject) });
    status('注册成功。现在可以使用设备密钥登录。', 'success');
  } catch (error) { status(error.name === 'NotAllowedError' ? '操作被取消或超时，请重试。' : error.message, 'error'); }
  finally { setBusy(false); }
}

async function login() {
  const username = $('username').value.trim();
  if (!username) return status('请输入注册过的用户名', 'error');
  if (!window.PublicKeyCredential) return status('当前浏览器不支持 WebAuthn', 'error');
  setBusy(true); status('请在设备上确认你的 Passkey…', 'loading');
  try {
    const options = await call('/api/auth/login/options', {username});
    const publicKey = {...options, challenge: decode(options.challenge), allowCredentials: options.allowCredentials.map(item => ({...item, id: decode(item.id)}))};
    const credential = await navigator.credentials.get({publicKey});
    const response = credential.response;
    await call('/api/auth/login/verify', { username, credentialId: encode(credential.rawId), clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData), signature: encode(response.signature) });
    status(`登录成功，欢迎回来，${username}。`, 'success');
  } catch (error) { status(error.name === 'NotAllowedError' ? '操作被取消或超时，请重试。' : error.message, 'error'); }
  finally { setBusy(false); }
}

$('register').addEventListener('click', register);
$('login').addEventListener('click', login);
