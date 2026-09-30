const COOKIE = 'fulkoli_auth'
const MAX_AGE = 60 * 60 * 24 * 30

function credentials() {
  const env = (globalThis as any).Netlify?.env
  return {
    user: env?.get('ADMIN_USER') || 'admin',
    pass: env?.get('ADMIN_PASS') || '0000',
  }
}

async function sessionToken() {
  const { user, pass } = credentials()
  const data = new TextEncoder().encode(`fulkoli:${user}:${pass}`)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('')
}

function readCookie(req: Request, name: string) {
  const header = req.headers.get('cookie') || ''
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return ''
}

function loginPage(error = '') {
  const html = `<!doctype html>
<html lang="bn">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login | Fulkoli Biscuit</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f7f4;color:#152e28;font:15px system-ui,"Noto Sans Bengali","Nirmala UI",sans-serif;padding:16px}
.box{width:100%;max-width:360px;background:#fff;border:1px solid #e1e9e4;border-radius:14px;padding:26px}
h1{font-size:22px;margin:0 0 4px}p{color:#64756e;margin:0 0 20px}
label{display:block;font-size:13px;color:#64756e;margin:0 0 6px}
input{width:100%;border:1px solid #cbd8d0;border-radius:8px;padding:11px;font:inherit;margin-bottom:14px}
button{width:100%;background:#176b50;color:#fff;border:0;border-radius:9px;padding:11px;font:inherit;font-weight:600;cursor:pointer}
.err{background:#fbeceb;color:#a94236;border-radius:8px;padding:10px;margin-bottom:14px;font-size:13px}
</style>
</head>
<body>
<form class="box" method="post" action="/login">
<h1>Fulkoli Biscuit</h1>
<p>Sales Manager — লগইন করুন</p>
${error ? `<div class="err">${error}</div>` : ''}
<label for="user">User ID</label>
<input id="user" name="user" autocomplete="username" required autofocus>
<label for="pass">Password</label>
<input id="pass" name="pass" type="password" autocomplete="current-password" required>
<button type="submit">Login</button>
</form>
</body>
</html>`
  return new Response(html, {
    status: error ? 401 : 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  })
}

export default async (req: Request) => {
  const url = new URL(req.url)

  if (url.pathname === '/logout') {
    return new Response(null, {
      status: 303,
      headers: {
        location: '/',
        'set-cookie': `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
      },
    })
  }

  if (url.pathname === '/login' && req.method === 'POST') {
    const form = await req.formData()
    const { user, pass } = credentials()
    if (String(form.get('user') || '').trim() === user && String(form.get('pass') || '') === pass) {
      return new Response(null, {
        status: 303,
        headers: {
          location: '/',
          'set-cookie': `${COOKIE}=${await sessionToken()}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
        },
      })
    }
    return loginPage('User ID অথবা Password ভুল হয়েছে।')
  }

  if (readCookie(req, COOKIE) === (await sessionToken())) return

  return loginPage()
}

export const config = {
  path: '/*',
}
