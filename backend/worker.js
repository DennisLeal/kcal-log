const PRODUCT_AMOUNT = 7900;
const PRODUCT_CURRENCY = 'PHP';
const ACCESS_CODE_TTL_MS = 10 * 60 * 1000;
const MAX_WEBHOOK_AGE_SECONDS = 5 * 60;

function jsonResponse(body, status = 200, origin = null, env = {}) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  });
  if (origin && origin === env.APP_ORIGIN) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    headers.set('Vary', 'Origin');
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function allowedOrigin(origin, env) {
  return !origin || origin === env.APP_ORIGIN;
}

function validEmail(value) {
  return typeof value === 'string' &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim())
    ? value.trim().toLowerCase()
    : null;
}

function randomHex(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function randomToken(byteLength = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

function parseSignatureHeader(header) {
  if (typeof header !== 'string') return null;
  const parts = Object.create(null);
  for (const part of header.split(',')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    parts[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
  }
  if (!parts.t || !/^\d+$/.test(parts.t)) return null;
  return { timestamp: parts.t, test: parts.te || '', live: parts.li || '' };
}

async function verifyWebhookSignature(rawBody, header, secret, livemode, now = Date.now()) {
  if (!(rawBody instanceof Uint8Array) || !secret) return false;
  const signature = parseSignatureHeader(header);
  if (!signature) return false;

  const timestamp = Number(signature.timestamp);
  if (!Number.isSafeInteger(timestamp) ||
      Math.abs(now / 1000 - timestamp) > MAX_WEBHOOK_AGE_SECONDS) return false;

  const supplied = livemode ? signature.live : signature.test;
  if (!/^[a-f\d]{64}$/i.test(supplied)) return false;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const prefix = new TextEncoder().encode(`${signature.timestamp}.`);
  const message = new Uint8Array(prefix.length + rawBody.length);
  message.set(prefix);
  message.set(rawBody, prefix.length);
  const expected = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const actual = new Uint8Array(supplied.match(/.{2}/g).map(part => parseInt(part, 16)));
  let difference = expected.length ^ actual.length;
  for (let index = 0; index < expected.length; index += 1) {
    difference |= expected[index] ^ (actual[index] || 0);
  }
  return difference === 0;
}

function getWebhookEvent(payload) {
  const wrapper = payload?.data;
  const attributes = wrapper?.attributes;
  const eventType = wrapper?.type === 'event' ? attributes?.type : wrapper?.type;
  const resource = wrapper?.type === 'event' ? attributes?.data : wrapper?.data;
  const livemode = wrapper?.type === 'event' ? attributes?.livemode : wrapper?.livemode;
  const eventId = wrapper?.type === 'event' ? wrapper?.id : (payload?.id || wrapper?.id);
  if (!eventType || !resource || typeof livemode !== 'boolean') return null;
  return { eventId: eventId || resource.id || null, eventType, livemode, resource };
}

function validatePaidCheckout(resource, order) {
  const attributes = resource?.attributes;
  if (!resource?.id ||
      resource.id !== order.checkout_session_id ||
      !attributes ||
      attributes.reference_number !== order.id) return false;
  const paidPayment = (attributes.payments || []).find(payment => {
    const paymentAttributes = payment?.attributes || payment;
    return paymentAttributes?.status === 'paid';
  });
  if (!paidPayment) return false;
  const payment = paidPayment.attributes || paidPayment;
  return payment.amount === order.amount &&
    String(payment.currency).toUpperCase() === order.currency;
}

function paymentConfigurationReady(env) {
  return Boolean(
    env.PAYMONGO_SECRET_KEY &&
    env.PAYMONGO_WEBHOOK_SECRET &&
    isValidEmailRelayURL(env.EMAIL_RELAY_URL) &&
    typeof env.EMAIL_RELAY_HMAC_SECRET === 'string' &&
    env.EMAIL_RELAY_HMAC_SECRET.length >= 32 &&
    env.APP_URL &&
    env.APP_ORIGIN &&
    env.ALERT_EMAIL_TO &&
    (env.PAYMONGO_MODE === 'test'
      ? env.PAYMONGO_SECRET_KEY.startsWith('sk_test_')
      : env.PAYMONGO_MODE === 'live' && env.PAYMONGO_SECRET_KEY.startsWith('sk_live_'))
  );
}

function isValidEmailRelayURL(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' &&
      url.hostname === 'script.google.com' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      /^\/macros\/s\/[^/]+\/exec$/.test(url.pathname);
  } catch {
    return false;
  }
}

async function readJson(request, maxBytes = 32 * 1024) {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > maxBytes) return null;
  const text = await request.text();
  if (new TextEncoder().encode(text).length > maxBytes) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function checkRateLimit(db, key, maximum, windowMs, now = Date.now()) {
  const windowStart = Math.floor(now / windowMs) * windowMs;
  const result = await db.prepare(`
    INSERT INTO rate_limits (rate_key, window_start, request_count)
    VALUES (?1, ?2, 1)
    ON CONFLICT(rate_key) DO UPDATE SET
      request_count = CASE
        WHEN rate_limits.window_start = excluded.window_start
          THEN rate_limits.request_count + 1
        ELSE 1
      END,
      window_start = excluded.window_start
    RETURNING request_count
  `).bind(key, windowStart).first();
  return Number(result?.request_count || 0) <= maximum;
}

async function sendEmail(env, { to, subject, text }) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomToken(18);
  const payload = JSON.stringify({ to, subject, text });
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.EMAIL_RELAY_HMAC_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const message = new TextEncoder().encode(`${timestamp}\n${nonce}\n${payload}`);
  const signatureBytes = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const signature = Array.from(
    signatureBytes,
    byte => byte.toString(16).padStart(2, '0')
  ).join('');

  let response;
  try {
    response = await fetch(env.EMAIL_RELAY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ timestamp, nonce, payload, signature }),
      signal: AbortSignal.timeout(15000)
    });
  } catch (error) {
    console.error('Email delivery request failed:', error.message);
    throw new Error('Email delivery failed.');
  }
  let result;
  try {
    result = await response.json();
  } catch {
    console.error('Email relay returned an invalid response with status', response.status);
    throw new Error('Email delivery failed.');
  }
  if (!response.ok || result?.ok !== true) {
    console.error('Email relay failed with status', response.status);
    throw new Error('Email delivery failed.');
  }
}

async function sendPendingOrderEmails(db, env, orderId) {
  const order = await db.prepare(
    'SELECT * FROM orders WHERE id = ?1 AND status = ?2'
  ).bind(orderId, 'paid').first();
  if (!order) return;

  if (!order.buyer_email_sent_at) {
    await sendEmail(env, {
      to: order.email,
      subject: 'Your Kcal Log lifetime purchase is confirmed',
      text: `Your ₱79 Kcal Log lifetime purchase is confirmed.\n\nOpen ${env.APP_URL} and use "Restore lifetime access" with this email address to receive a one-time access code. Your food logs remain on your device and are not sent to us.`
    });
    await db.prepare(
      'UPDATE orders SET buyer_email_sent_at = ?1 WHERE id = ?2 AND buyer_email_sent_at IS NULL'
    ).bind(Date.now(), orderId).run();
  }

  const latestOrder = await db.prepare(
    'SELECT * FROM orders WHERE id = ?1 AND status = ?2'
  ).bind(orderId, 'paid').first();
  if (latestOrder && !latestOrder.owner_email_sent_at) {
    await sendEmail(env, {
      to: env.ALERT_EMAIL_TO,
      subject: 'Kcal Log lifetime purchase confirmed',
      text: `A lifetime purchase was confirmed.\nOrder: ${latestOrder.id}\nBuyer email: ${latestOrder.email}\nAmount: PHP 79.00\nPayMongo mode: ${env.PAYMONGO_MODE}`
    });
    await db.prepare(
      'UPDATE orders SET owner_email_sent_at = ?1 WHERE id = ?2 AND owner_email_sent_at IS NULL'
    ).bind(Date.now(), orderId).run();
  }
}

async function createCheckout(order, env) {
  const response = await fetch('https://api.paymongo.com/v2/checkout_sessions', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${btoa(`${env.PAYMONGO_SECRET_KEY}:`)}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      data: {
        attributes: {
          line_items: [{
            name: 'Kcal Log lifetime access',
            amount: order.amount,
            currency: order.currency,
            quantity: 1
          }],
          payment_method_types: ['qrph'],
          billing: { email: order.email },
          success_url: `${env.APP_URL}?purchase=complete&order=${encodeURIComponent(order.id)}`,
          cancel_url: `${env.APP_URL}?purchase=cancelled`,
          reference_number: order.id,
          send_email_receipt: true,
          metadata: { product: 'kcal-log-lifetime', order_id: order.id }
        }
      }
    }),
    signal: AbortSignal.timeout(15000)
  });
  const payload = await response.json();
  if (!response.ok) {
    console.error('PayMongo checkout creation failed with status', response.status);
    throw new Error('Unable to create checkout session.');
  }
  const session = payload?.data;
  const checkoutUrl = session?.attributes?.checkout_url;
  if (!session?.id ||
      typeof checkoutUrl !== 'string' ||
      !checkoutUrl.startsWith('https://checkout.paymongo.com/')) {
    throw new Error('PayMongo returned an invalid checkout session.');
  }
  return { id: session.id, url: checkoutUrl };
}

async function handleCheckout(request, env) {
  if (!paymentConfigurationReady(env)) {
    return jsonResponse({ error: 'lifetime checkout is not configured' }, 503, request.headers.get('Origin'), env);
  }
  const body = await readJson(request);
  if (!body) return jsonResponse({ error: 'invalid request body' }, 400, request.headers.get('Origin'), env);
  const email = validEmail(body.email);
  if (!email) return jsonResponse({ error: 'valid email required' }, 400, request.headers.get('Origin'), env);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await sha256Hex(`checkout:${ip}`);
  if (!await checkRateLimit(env.PAYMENTS_DB, ipHash, 5, 60 * 60 * 1000)) {
    return jsonResponse({ error: 'too many checkout attempts; try again later' }, 429, request.headers.get('Origin'), env);
  }

  const order = {
    id: crypto.randomUUID(),
    email,
    amount: PRODUCT_AMOUNT,
    currency: PRODUCT_CURRENCY
  };
  await env.PAYMENTS_DB.prepare(`
    INSERT INTO orders (id, email, amount, currency, status, created_at)
    VALUES (?1, ?2, ?3, ?4, 'creating', ?5)
  `).bind(order.id, order.email, order.amount, order.currency, Date.now()).run();

  try {
    const session = await createCheckout(order, env);
    await env.PAYMENTS_DB.prepare(`
      UPDATE orders
      SET status = 'pending', checkout_session_id = ?1
      WHERE id = ?2 AND status = 'creating'
    `).bind(session.id, order.id).run();
    return jsonResponse(
      { checkoutUrl: session.url, orderId: order.id },
      200,
      request.headers.get('Origin'),
      env
    );
  } catch (error) {
    await env.PAYMENTS_DB.prepare(
      "UPDATE orders SET status = 'failed' WHERE id = ?1 AND status = 'creating'"
    ).bind(order.id).run();
    console.error('Checkout creation failed:', error.message);
    return jsonResponse(
      { error: 'could not start checkout; please try again' },
      502,
      request.headers.get('Origin'),
      env
    );
  }
}

async function handleSendAccessCode(request, env) {
  const body = await readJson(request);
  if (!body) return jsonResponse({ error: 'invalid request body' }, 400, request.headers.get('Origin'), env);
  const email = validEmail(body.email);
  if (!email) return jsonResponse({ error: 'valid email required' }, 400, request.headers.get('Origin'), env);
  if (!paymentConfigurationReady(env)) {
    return jsonResponse({ error: 'email recovery is not configured' }, 503, request.headers.get('Origin'), env);
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await sha256Hex(`access-ip:${ip}`);
  const emailHash = await sha256Hex(`access-email:${email}`);
  if (!await checkRateLimit(env.PAYMENTS_DB, ipHash, 20, 60 * 60 * 1000) ||
      !await checkRateLimit(env.PAYMENTS_DB, emailHash, 5, 60 * 60 * 1000)) {
    return jsonResponse({ error: 'too many requests; try again later' }, 429, request.headers.get('Origin'), env);
  }

  const orderId = typeof body.orderId === 'string' ? body.orderId : null;
  const order = await env.PAYMENTS_DB.prepare(`
    SELECT id, email FROM orders
    WHERE status = 'paid' AND email = ?1
      AND (?2 IS NULL OR id = ?2)
    ORDER BY paid_at DESC
    LIMIT 1
  `).bind(email, orderId).first();

  if (order) {
    const code = randomHex(12).toUpperCase();
    const codeHash = await sha256Hex(`${email}:${code}`);
    const expiresAt = Date.now() + ACCESS_CODE_TTL_MS;
    await env.PAYMENTS_DB.prepare(`
      INSERT INTO access_codes (email, order_id, code_hash, expires_at)
      VALUES (?1, ?2, ?3, ?4)
      ON CONFLICT(email) DO UPDATE SET
        order_id = excluded.order_id,
        code_hash = excluded.code_hash,
        expires_at = excluded.expires_at
    `).bind(email, order.id, codeHash, expiresAt).run();
    try {
      await sendEmail(env, {
        to: email,
        subject: 'Your Kcal Log access code',
        text: `Your one-time Kcal Log access code is ${code}.\n\nIt expires in 10 minutes. Enter it in Kcal Log to unlock or restore lifetime access. If you did not request this code, you can ignore this message.`
      });
    } catch (error) {
      console.error('Access code email delivery failed:', error.message);
      await env.PAYMENTS_DB.prepare(
        'DELETE FROM access_codes WHERE email = ?1 AND code_hash = ?2'
      ).bind(email, codeHash).run();
    }
  }

  return jsonResponse(
    { ok: true },
    200,
    request.headers.get('Origin'),
    env
  );
}

async function handleRedeemAccessCode(request, env) {
  const body = await readJson(request);
  if (!body) return jsonResponse({ error: 'invalid request body' }, 400, request.headers.get('Origin'), env);
  const email = validEmail(body.email);
  const code = typeof body.code === 'string' ? body.code.trim().toUpperCase() : '';
  if (!email || !/^[A-F0-9]{24}$/.test(code)) {
    return jsonResponse({ error: 'valid email and access code required' }, 400, request.headers.get('Origin'), env);
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await sha256Hex(`redeem-ip:${ip}`);
  const emailHash = await sha256Hex(`redeem-email:${email}`);
  if (!await checkRateLimit(env.PAYMENTS_DB, ipHash, 30, 60 * 60 * 1000) ||
      !await checkRateLimit(env.PAYMENTS_DB, emailHash, 10, 60 * 60 * 1000)) {
    return jsonResponse({ error: 'too many code attempts; request a new code later' }, 429, request.headers.get('Origin'), env);
  }

  const codeHash = await sha256Hex(`${email}:${code}`);
  const deletion = await env.PAYMENTS_DB.prepare(`
    DELETE FROM access_codes
    WHERE email = ?1 AND code_hash = ?2 AND expires_at > ?3
      AND EXISTS (
        SELECT 1 FROM orders
        WHERE orders.id = access_codes.order_id
          AND orders.email = access_codes.email
          AND orders.status = 'paid'
      )
    RETURNING order_id
  `).bind(email, codeHash, Date.now()).first();
  if (!deletion?.order_id) {
    return jsonResponse(
      { error: 'code is invalid or expired; request a new one' },
      400,
      request.headers.get('Origin'),
      env
    );
  }

  const accessToken = randomToken();
  await env.PAYMENTS_DB.prepare(`
    INSERT INTO access_tokens (token_hash, email, order_id, created_at)
    VALUES (?1, ?2, ?3, ?4)
  `).bind(await sha256Hex(accessToken), email, deletion.order_id, Date.now()).run();
  return jsonResponse({ accessToken }, 200, request.headers.get('Origin'), env);
}

async function findPaidAccess(request, env) {
  const token = request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256Hex(token);
  const order = await env.PAYMENTS_DB.prepare(`
    SELECT orders.id
    FROM access_tokens
    JOIN orders ON orders.id = access_tokens.order_id
      AND orders.email = access_tokens.email
    WHERE access_tokens.token_hash = ?1 AND orders.status = 'paid'
    LIMIT 1
  `).bind(tokenHash).first();
  return order ? { tokenHash } : null;
}

async function handleAccessStatus(request, env) {
  const hasToken = Boolean(request.headers.get('Authorization'));
  const access = await findPaidAccess(request, env);
  const status = access ? 200 : (hasToken ? 200 : 401);
  return jsonResponse({ active: Boolean(access) }, status, request.headers.get('Origin'), env);
}

const FOOD_PHOTO_MAX_BASE64 = 1_400_000;
const FOOD_PHOTO_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const FOOD_PHOTO_DAY_MS = 24 * 60 * 60 * 1000;
const MACRO_FIELDS = ['kcal', 'protein', 'carbs', 'fat'];

const FOOD_PROMPT = `You are a nutrition analyst for a Filipino calorie-tracking app.
Identify the food in the photo and break it into its main ingredients/components.
For each component give its share of the total food weight (shares must add up to about 1)
and typical nutrition values per 100 g in the state shown (cooked or raw as stated below).
Prefer Philippine food composition values for local dishes (adobo, sinigang, pancit, rice, etc.).
Do not multiply by the portion weight; only give per-100 g values.
If the photo does not contain food, return an empty components list and confidence 0.`;

const FOOD_SCHEMA = {
  type: 'OBJECT',
  properties: {
    dish: { type: 'STRING' },
    confidence: { type: 'NUMBER' },
    components: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          name: { type: 'STRING' },
          share: { type: 'NUMBER' },
          kcal_per_100g: { type: 'NUMBER' },
          protein_per_100g: { type: 'NUMBER' },
          carbs_per_100g: { type: 'NUMBER' },
          fat_per_100g: { type: 'NUMBER' }
        },
        required: ['name', 'share', 'kcal_per_100g', 'protein_per_100g', 'carbs_per_100g', 'fat_per_100g']
      }
    }
  },
  required: ['dish', 'confidence', 'components']
};

function clampNumber(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return Math.min(max, Math.max(min, number));
}

function computeFoodNutrition(analysis, grams) {
  const rawComponents = Array.isArray(analysis?.components) ? analysis.components.slice(0, 12) : [];
  const components = [];
  for (const item of rawComponents) {
    const share = clampNumber(item?.share, 0, 1);
    const per100 = {
      kcal: clampNumber(item?.kcal_per_100g, 0, 900),
      protein: clampNumber(item?.protein_per_100g, 0, 100),
      carbs: clampNumber(item?.carbs_per_100g, 0, 100),
      fat: clampNumber(item?.fat_per_100g, 0, 100)
    };
    if (!share || MACRO_FIELDS.some(field => per100[field] === null)) continue;
    components.push({
      name: String(item.name || 'Food').slice(0, 80),
      share,
      per100
    });
  }
  const shareTotal = components.reduce((sum, item) => sum + item.share, 0);
  if (!components.length || shareTotal <= 0) return null;

  const blended = { kcal: 0, protein: 0, carbs: 0, fat: 0 };
  for (const item of components) {
    for (const field of MACRO_FIELDS) blended[field] += (item.share / shareTotal) * item.per100[field];
  }
  const factor = grams / 100;
  const totals = {
    kcal: Math.round(blended.kcal * factor),
    protein: Math.round(blended.protein * factor * 10) / 10,
    carbs: Math.round(blended.carbs * factor * 10) / 10,
    fat: Math.round(blended.fat * factor * 10) / 10
  };
  const atwater = blended.protein * 4 + blended.carbs * 4 + blended.fat * 9;
  const consistent = blended.kcal === 0
    ? atwater < 20
    : Math.abs(atwater - blended.kcal) / blended.kcal <= 0.35;
  return {
    totals,
    per100g: {
      kcal: Math.round(blended.kcal),
      protein: Math.round(blended.protein * 10) / 10,
      carbs: Math.round(blended.carbs * 10) / 10,
      fat: Math.round(blended.fat * 10) / 10
    },
    components: components.map(item => ({ name: item.name, share: Math.round((item.share / shareTotal) * 100) / 100 })),
    consistent
  };
}

async function callGemini(env, image, mimeType, grams, state, extraFat) {
  const model = /^[a-z0-9.\-]{3,60}$/.test(env.GEMINI_MODEL || '') ? env.GEMINI_MODEL : 'gemini-3.1-flash-lite';
  const context = `The user weighed this portion at ${grams} g. The food is ${state === 'raw' ? 'raw' : state === 'cooked' ? 'cooked' : 'in the state shown'}.` +
    (extraFat ? ' Oil, butter or sauce was added during cooking; include it in the values.' : '');
  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `${FOOD_PROMPT}\n${context}` }, { inline_data: { mime_type: mimeType, data: image } }] }],
        generationConfig: { responseMimeType: 'application/json', responseSchema: FOOD_SCHEMA, temperature: 0.2 }
      }),
      signal: AbortSignal.timeout(25000)
    }
  );
  if (response.status === 429) return { quota: true };
  if (!response.ok) throw new Error(`Gemini request failed (${response.status})`);
  const data = await response.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  try {
    return { analysis: JSON.parse(text) };
  } catch {
    return { analysis: null };
  }
}

async function handleAnalyzeFood(request, env) {
  const origin = request.headers.get('Origin');
  if (!env.GEMINI_API_KEY) {
    return jsonResponse({ error: 'photo analysis is not configured' }, 503, origin, env);
  }
  const access = await findPaidAccess(request, env);
  if (!access) {
    return jsonResponse({ error: 'photo analysis is a lifetime-access feature' }, 403, origin, env);
  }
  const body = await readJson(request, FOOD_PHOTO_MAX_BASE64 + 4096);
  if (!body) return jsonResponse({ error: 'invalid or oversized request' }, 400, origin, env);

  const grams = clampNumber(body.grams, 1, 5000);
  const image = typeof body.image === 'string' ? body.image : '';
  if (grams === null || Number(body.grams) <= 0 ||
      !FOOD_PHOTO_MIME_TYPES.includes(body.mimeType) ||
      !image || image.length > FOOD_PHOTO_MAX_BASE64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(image)) {
    return jsonResponse({ error: 'a photo and a weight in grams are required' }, 400, origin, env);
  }
  const state = ['cooked', 'raw', 'unknown'].includes(body.state) ? body.state : 'unknown';

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const dailyCap = Number(env.GEMINI_DAILY_CAP) > 0 ? Number(env.GEMINI_DAILY_CAP) : 800;
  if (!await checkRateLimit(env.PAYMENTS_DB, `food-token:${access.tokenHash}`, 40, FOOD_PHOTO_DAY_MS) ||
      !await checkRateLimit(env.PAYMENTS_DB, `food-ip:${await sha256Hex(ip)}`, 60, FOOD_PHOTO_DAY_MS)) {
    return jsonResponse({ error: 'daily photo limit reached; try again tomorrow' }, 429, origin, env);
  }
  if (!await checkRateLimit(env.PAYMENTS_DB, 'food-global', dailyCap, FOOD_PHOTO_DAY_MS)) {
    return jsonResponse({ error: 'photo analysis is busy; try again later' }, 503, origin, env);
  }

  let result;
  try {
    result = await callGemini(env, image, body.mimeType, grams, state, body.extraFat === true);
  } catch (error) {
    console.error('Food analysis failed:', error.message);
    return jsonResponse({ error: 'photo analysis is unavailable right now' }, 502, origin, env);
  }
  if (result.quota) {
    return jsonResponse({ error: 'photo analysis is busy; try again later' }, 503, origin, env);
  }
  const nutrition = computeFoodNutrition(result.analysis, grams);
  if (!nutrition) {
    return jsonResponse({ error: 'could not recognise food in this photo; try a clearer shot' }, 422, origin, env);
  }
  const confidence = clampNumber(result.analysis.confidence, 0, 1) ?? 0;
  return jsonResponse({
    dish: String(result.analysis.dish || 'Food').slice(0, 120),
    confidence,
    grams,
    ...nutrition
  }, 200, origin, env);
}

async function handleWebhook(request, env) {
  if (!env.PAYMONGO_WEBHOOK_SECRET) return jsonResponse({ error: 'webhook is not configured' }, 503);
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > 256 * 1024) return jsonResponse({ error: 'webhook body is too large' }, 413);
  const rawBody = new Uint8Array(await request.arrayBuffer());
  if (rawBody.length > 256 * 1024) return jsonResponse({ error: 'webhook body is too large' }, 413);

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(rawBody));
  } catch {
    return jsonResponse({ error: 'invalid webhook payload' }, 400);
  }
  const event = getWebhookEvent(payload);
  if (!event) return jsonResponse({ error: 'invalid webhook event' }, 400);
  if (!await verifyWebhookSignature(
    rawBody,
    request.headers.get('Paymongo-Signature'),
    env.PAYMONGO_WEBHOOK_SECRET,
    event.livemode
  )) {
    return jsonResponse({ error: 'invalid webhook signature' }, 401);
  }
  if (event.livemode !== (env.PAYMONGO_MODE === 'live') ||
      event.eventType !== 'checkout_session.payment.paid') {
    return jsonResponse({ received: true, ignored: true });
  }

  const attributes = event.resource.attributes || {};
  const paidPayment = (attributes.payments || []).find(payment => {
    const paymentAttributes = payment?.attributes || payment;
    return paymentAttributes?.status === 'paid';
  });
  const payment = paidPayment?.attributes || paidPayment;
  const eventId = event.eventId ||
    `${event.eventType}:${event.resource.id}:${payment?.id || ''}`;
  const order = await env.PAYMENTS_DB.prepare(`
    SELECT * FROM orders
    WHERE id = ?1 AND checkout_session_id = ?2
      AND status IN ('pending', 'paid')
    LIMIT 1
  `).bind(attributes.reference_number, event.resource.id).first();
  if (!order || !validatePaidCheckout(event.resource, order)) {
    return jsonResponse({ received: true, ignored: true });
  }

  const results = await env.PAYMENTS_DB.batch([
    env.PAYMENTS_DB.prepare(`
      INSERT OR IGNORE INTO processed_events (event_id, processed_at, order_id)
      VALUES (?1, ?2, ?3)
    `).bind(eventId, Date.now(), order.id),
    env.PAYMENTS_DB.prepare(`
      UPDATE orders
      SET status = 'paid',
          paid_at = COALESCE(paid_at, ?1),
          payment_id = COALESCE(payment_id, ?2)
      WHERE id = ?3 AND checkout_session_id = ?4
        AND status IN ('pending', 'paid')
        AND EXISTS (
          SELECT 1 FROM processed_events
          WHERE event_id = ?5 AND order_id = ?3
        )
    `).bind(Date.now(), payment.id || null, order.id, event.resource.id, eventId)
  ]);
  if (!results?.[1]?.meta?.changes) {
    return jsonResponse({ received: true, ignored: true });
  }

  try {
    await sendPendingOrderEmails(env.PAYMENTS_DB, env, order.id);
  } catch (error) {
    console.error('Paid order email fulfillment failed:', error.message);
    return jsonResponse({ error: 'email fulfillment failed' }, 500);
  }
  return jsonResponse({ received: true });
}

async function handleHealth(env) {
  try {
    await env.PAYMENTS_DB.prepare('SELECT 1 AS ok').first();
    return jsonResponse({ status: 'ok' });
  } catch {
    return jsonResponse({ status: 'unavailable' }, 503);
  }
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (request.method === 'OPTIONS') {
    if (!allowedOrigin(origin, env)) {
      return jsonResponse({ error: 'origin not allowed' }, 403);
    }
    const headers = new Headers({
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      'Cache-Control': 'no-store',
      'Vary': 'Origin'
    });
    if (origin) headers.set('Access-Control-Allow-Origin', origin);
    return new Response(null, { status: 204, headers });
  }
  if (url.pathname.startsWith('/api/') && !allowedOrigin(origin, env)) {
    return jsonResponse({ error: 'origin not allowed' }, 403);
  }
  if (request.method === 'GET' && url.pathname === '/health') return handleHealth(env);
  if (request.method === 'POST' && url.pathname === '/webhooks/paymongo') return handleWebhook(request, env);
  if (request.method === 'POST' && url.pathname === '/api/checkout') return handleCheckout(request, env);
  if (request.method === 'POST' && url.pathname === '/api/access/send-code') return handleSendAccessCode(request, env);
  if (request.method === 'POST' && url.pathname === '/api/access/redeem-code') return handleRedeemAccessCode(request, env);
  if (request.method === 'GET' && url.pathname === '/api/access/status') return handleAccessStatus(request, env);
  if (request.method === 'POST' && url.pathname === '/api/analyze-food') return handleAnalyzeFood(request, env);
  return jsonResponse({ error: 'not found' }, 404, origin, env);
}

export {
  checkRateLimit,
  computeFoodNutrition,
  getWebhookEvent,
  handleRequest,
  isValidEmailRelayURL,
  parseSignatureHeader,
  paymentConfigurationReady,
  sha256Hex,
  sendEmail,
  validEmail,
  validatePaidCheckout,
  verifyWebhookSignature
};

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error('Worker request failed:', error.message);
      return jsonResponse(
        { error: 'server error; please try again later' },
        500,
        request.headers.get('Origin'),
        env
      );
    }
  }
};
