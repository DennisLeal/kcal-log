import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import worker, {
  checkRateLimit,
  computeFoodNutrition,
  getWebhookEvent,
  isValidEmailRelayURL,
  parseSignatureHeader,
  paymentConfigurationReady,
  sendEmail,
  validEmail,
  validatePaidCheckout,
  verifyWebhookSignature
} from './worker.js';

const env = { APP_ORIGIN: 'https://dennisleal.github.io' };

test('email validation normalizes valid addresses and rejects malformed input', () => {
  assert.equal(validEmail('  User@Example.com  '), 'user@example.com');
  assert.equal(validEmail('invalid'), null);
  assert.equal(validEmail('user@localhost'), null);
  assert.equal(validEmail('x'.repeat(245) + '@example.com'), null);
});

test('Google Apps Script relay URL validation only accepts HTTPS web-app endpoints', () => {
  assert.equal(
    isValidEmailRelayURL('https://script.google.com/macros/s/AbCd123/exec'),
    true
  );
  assert.equal(
    isValidEmailRelayURL('https://script.google.com.evil.example/macros/s/AbCd123/exec'),
    false
  );
  assert.equal(
    isValidEmailRelayURL('http://script.google.com/macros/s/AbCd123/exec'),
    false
  );
  assert.equal(
    isValidEmailRelayURL('https://script.google.com/macros/s/AbCd123/dev'),
    false
  );
});

test('payment readiness requires a valid relay URL and HMAC secret', () => {
  const config = {
    PAYMONGO_SECRET_KEY: 'sk_test_example',
    PAYMONGO_WEBHOOK_SECRET: 'whsk_test_example',
    EMAIL_RELAY_URL: 'https://script.google.com/macros/s/AbCd123/exec',
    EMAIL_RELAY_HMAC_SECRET: 'a'.repeat(64),
    APP_URL: 'https://dennisleal.github.io/kcal-log/',
    APP_ORIGIN: env.APP_ORIGIN,
    ALERT_EMAIL_TO: 'owner@example.com',
    PAYMONGO_MODE: 'test'
  };

  assert.equal(paymentConfigurationReady(config), true);
  assert.equal(paymentConfigurationReady({ ...config, EMAIL_RELAY_HMAC_SECRET: '' }), false);
  assert.equal(paymentConfigurationReady({ ...config, EMAIL_RELAY_HMAC_SECRET: 'short' }), false);
  assert.equal(paymentConfigurationReady({
    ...config,
    EMAIL_RELAY_URL: 'https://attacker.example/relay'
  }), false);
});

test('email sending signs the exact payload and rejects unsuccessful relay responses', async () => {
  const originalFetch = globalThis.fetch;
  const originalConsoleError = console.error;
  const secret = 'relay-secret'.repeat(6);
  const email = {
    to: 'buyer@example.com',
    subject: 'Purchase confirmed',
    text: 'Your access code is ABC123.'
  };
  const relayURL = 'https://script.google.com/macros/s/AbCd123/exec';
  let requestEnvelope;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, relayURL);
    assert.equal(options.method, 'POST');
    requestEnvelope = JSON.parse(options.body);
    const expected = createHmac('sha256', secret)
      .update(`${requestEnvelope.timestamp}\n${requestEnvelope.nonce}\n${requestEnvelope.payload}`)
      .digest('hex');
    assert.equal(requestEnvelope.signature, expected);
    assert.deepEqual(JSON.parse(requestEnvelope.payload), email);
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };

  try {
    await sendEmail({
      EMAIL_RELAY_URL: relayURL,
      EMAIL_RELAY_HMAC_SECRET: secret
    }, email);
    assert.match(requestEnvelope.nonce, /^[A-Za-z0-9_-]{24}$/);

    globalThis.fetch = async () => new Response(
      JSON.stringify({ ok: false }),
      { status: 200 }
    );
    console.error = () => {};
    await assert.rejects(
      sendEmail({
        EMAIL_RELAY_URL: relayURL,
        EMAIL_RELAY_HMAC_SECRET: secret
      }, email),
      /Email delivery failed/
    );
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalConsoleError;
  }
});

test('PayMongo signatures parse required timestamp and mode-specific signatures', () => {
  assert.deepEqual(parseSignatureHeader('t=1700000000,te=abc,li=def'), {
    timestamp: '1700000000',
    test: 'abc',
    live: 'def'
  });
  assert.equal(parseSignatureHeader('te=abc'), null);
  assert.equal(parseSignatureHeader('t=not-a-timestamp,te=abc'), null);
});

test('webhook signature verifies raw bytes, mode, and timestamp freshness', async () => {
  const secret = 'whsk_test_signing_secret';
  const timestamp = String(Math.floor(Date.now() / 1000));
  const rawBody = new TextEncoder().encode('{"data":{"type":"event"}}');
  const signature = createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest('hex');
  const header = `t=${timestamp},te=${signature},li=${'0'.repeat(64)}`;

  assert.equal(await verifyWebhookSignature(rawBody, header, secret, false), true);
  assert.equal(await verifyWebhookSignature(rawBody, header, secret, true), false);
  assert.equal(await verifyWebhookSignature(
    new TextEncoder().encode('{"data":{"type":"changed"}}'),
    header,
    secret,
    false
  ), false);
  assert.equal(await verifyWebhookSignature(
    rawBody,
    `t=${Number(timestamp) - 600},te=${signature}`,
    secret,
    false
  ), false);
});

test('webhook events accept PayMongo event envelopes and reject incomplete ones', () => {
  const event = getWebhookEvent({
    data: {
      id: 'evt_123',
      type: 'event',
      attributes: {
        type: 'checkout_session.payment.paid',
        livemode: false,
        data: { id: 'cs_123', attributes: {} }
      }
    }
  });
  assert.equal(event.eventId, 'evt_123');
  assert.equal(event.eventType, 'checkout_session.payment.paid');
  assert.equal(event.livemode, false);
  assert.equal(event.resource.id, 'cs_123');
  assert.equal(getWebhookEvent({ data: { type: 'event', attributes: {} } }), null);
});

test('paid checkout validation requires matching session, reference, amount, and currency', () => {
  const order = {
    id: 'order_123',
    checkout_session_id: 'cs_123',
    amount: 7900,
    currency: 'PHP'
  };
  const resource = {
    id: 'cs_123',
    attributes: {
      reference_number: 'order_123',
      payments: [{
        id: 'pay_123',
        attributes: { status: 'paid', amount: 7900, currency: 'PHP' }
      }]
    }
  };

  assert.equal(validatePaidCheckout(resource, order), true);
  assert.equal(validatePaidCheckout({ ...resource, id: 'cs_other' }, order), false);
  assert.equal(validatePaidCheckout({
    ...resource,
    attributes: { ...resource.attributes, reference_number: 'order_other' }
  }, order), false);
  assert.equal(validatePaidCheckout({
    ...resource,
    attributes: {
      ...resource.attributes,
      payments: [{ status: 'paid', amount: 7800, currency: 'PHP' }]
    }
  }, order), false);
  assert.equal(validatePaidCheckout({
    ...resource,
    attributes: {
      ...resource.attributes,
      payments: [{ status: 'paid', amount: 7900, currency: 'USD' }]
    }
  }, order), false);
});

test('rate limiting allows the configured count and resets for a new time window', async () => {
  const rows = new Map();
  const db = {
    prepare() {
      return {
        bind(key, windowStart) {
          return {
            async first() {
              const previous = rows.get(key);
              const requestCount = previous?.windowStart === windowStart
                ? previous.count + 1
                : 1;
              rows.set(key, { windowStart, count: requestCount });
              return { request_count: requestCount };
            }
          };
        }
      };
    }
  };

  assert.equal(await checkRateLimit(db, 'test', 2, 1000, 100), true);
  assert.equal(await checkRateLimit(db, 'test', 2, 1000, 200), true);
  assert.equal(await checkRateLimit(db, 'test', 2, 1000, 300), false);
  assert.equal(await checkRateLimit(db, 'test', 2, 1000, 1100), true);
});

test('OPTIONS preflight responds with an empty 204 and rejects other origins', async () => {
  const allowedResponse = await worker.fetch(new Request(
    'https://api.example/api/checkout',
    { method: 'OPTIONS', headers: { Origin: env.APP_ORIGIN } }
  ), env);
  assert.equal(allowedResponse.status, 204);
  assert.equal(await allowedResponse.text(), '');
  assert.equal(allowedResponse.headers.get('Access-Control-Allow-Origin'), env.APP_ORIGIN);

  const rejectedResponse = await worker.fetch(new Request(
    'https://api.example/api/checkout',
    { method: 'OPTIONS', headers: { Origin: 'https://malicious.example' } }
  ), env);
  assert.equal(rejectedResponse.status, 403);
});

test('API rejects cross-origin requests and unknown routes', async () => {
  const crossOrigin = await worker.fetch(new Request(
    'https://api.example/api/access/status',
    { headers: { Origin: 'https://malicious.example' } }
  ), env);
  assert.equal(crossOrigin.status, 403);

  const missing = await worker.fetch(new Request('https://api.example/not-found'), env);
  assert.equal(missing.status, 404);
});

test('health check reports D1 availability', async () => {
  const healthy = await worker.fetch(new Request('https://api.example/health'), {
    PAYMENTS_DB: { prepare: () => ({ first: async () => ({ ok: 1 }) }) }
  });
  assert.equal(healthy.status, 200);
  assert.deepEqual(await healthy.json(), { status: 'ok' });

  const unavailable = await worker.fetch(new Request('https://api.example/health'), {
    PAYMENTS_DB: { prepare: () => ({ first: async () => { throw new Error('offline'); } }) }
  });
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { status: 'unavailable' });
});

test('food nutrition is computed from per-100g values and the weighed portion', () => {
  const result = computeFoodNutrition({
    components: [
      { name: 'Rice', share: 0.6, kcal_per_100g: 130, protein_per_100g: 2.7, carbs_per_100g: 28, fat_per_100g: 0.3 },
      { name: 'Chicken adobo', share: 0.4, kcal_per_100g: 200, protein_per_100g: 20, carbs_per_100g: 3, fat_per_100g: 12 }
    ]
  }, 250);
  assert.equal(result.per100g.kcal, 158);
  assert.equal(result.totals.kcal, 395);
  assert.equal(result.totals.protein, 24.1);
  assert.equal(result.consistent, true);
  assert.equal(computeFoodNutrition({ components: [] }, 100), null);
  assert.equal(computeFoodNutrition({ components: [{ name: 'x', share: 1, kcal_per_100g: 'abc', protein_per_100g: 0, carbs_per_100g: 0, fat_per_100g: 0 }] }, 100), null);
});

test('food nutrition flags values whose calories disagree with the macros', () => {
  const result = computeFoodNutrition({
    components: [{ name: 'Mystery', share: 1, kcal_per_100g: 500, protein_per_100g: 5, carbs_per_100g: 10, fat_per_100g: 5 }]
  }, 100);
  assert.equal(result.consistent, false);
});

function foodRequest(body, token = 'valid-token') {
  return new Request('https://api.example/api/analyze-food', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body)
  });
}

function foodEnv({ paid = true, count = 1 } = {}) {
  return {
    ...env,
    GEMINI_API_KEY: 'test-key',
    PAYMENTS_DB: {
      prepare(sql) {
        return {
          bind() { return this; },
          first: async () => (sql.includes('rate_limits') ? { request_count: count } : (paid ? { id: 'order-1' } : null))
        };
      }
    }
  };
}

test('photo analysis is refused without lifetime access or configuration', async () => {
  const photo = { image: 'AAAA', mimeType: 'image/jpeg', grams: 150 };
  const unpaid = await worker.fetch(foodRequest(photo, 'trial-token'), foodEnv({ paid: false }));
  assert.equal(unpaid.status, 403);
  const noKey = await worker.fetch(foodRequest(photo), { ...foodEnv(), GEMINI_API_KEY: undefined });
  assert.equal(noKey.status, 503);
});

test('trial users get a limited number of photos via a trial id', async () => {
  const photo = { image: 'AAAA', mimeType: 'image/jpeg', grams: 150 };
  const trialRequest = (id) => new Request('https://api.example/api/analyze-food', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(id ? { 'X-Trial-Id': id } : {}) },
    body: JSON.stringify(photo)
  });
  const noId = await worker.fetch(trialRequest(null), foodEnv({ paid: false }));
  assert.equal(noId.status, 403);
  const badId = await worker.fetch(trialRequest('short'), foodEnv({ paid: false }));
  assert.equal(badId.status, 403);
  const used = await worker.fetch(trialRequest('trial-id-1234567890abcd'), foodEnv({ paid: false, count: 6 }));
  assert.equal(used.status, 403);
  assert.equal((await used.json()).code, 'trial-limit');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 429 });
  try {
    const allowed = await worker.fetch(trialRequest('trial-id-1234567890abcd'), foodEnv({ paid: false, count: 5 }));
    assert.equal(allowed.status, 503);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('tester invite codes unlock access without a paid order', async () => {
  const testerEnv = { ...foodEnv({ paid: false }), TESTER_CODES: 'short, friends-code-123456' };
  const status = (token) => worker.fetch(new Request('https://api.example/api/access/status', {
    headers: { Authorization: 'Bearer ' + token }
  }), testerEnv);
  assert.equal((await (await status('friends-code-123456')).json()).active, true);
  assert.equal((await (await status('short')).json()).active, false);
  assert.equal((await (await status('wrong-code-1234567')).json()).active, false);
});

test('photo analysis validates input and enforces rate limits', async () => {
  const badWeight = await worker.fetch(foodRequest({ image: 'AAAA', mimeType: 'image/jpeg', grams: 0 }), foodEnv());
  assert.equal(badWeight.status, 400);
  const badType = await worker.fetch(foodRequest({ image: 'AAAA', mimeType: 'image/gif', grams: 100 }), foodEnv());
  assert.equal(badType.status, 400);
  const limited = await worker.fetch(foodRequest({ image: 'AAAA', mimeType: 'image/jpeg', grams: 100 }), foodEnv({ count: 999 }));
  assert.equal(limited.status, 429);
});

test('photo analysis returns server-computed totals from the model response', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    assert.match(String(url), /generativelanguage\.googleapis\.com/);
    assert.equal(options.headers['x-goog-api-key'], 'test-key');
    return new Response(JSON.stringify({
      candidates: [{ content: { parts: [{ text: JSON.stringify({
        dish: 'Steamed rice',
        confidence: 0.9,
        components: [{ name: 'Rice', share: 1, kcal_per_100g: 130, protein_per_100g: 2.7, carbs_per_100g: 28, fat_per_100g: 0.3 }]
      }) }] } }]
    }), { status: 200 });
  };
  try {
    const response = await worker.fetch(foodRequest({ image: 'AAAA', mimeType: 'image/jpeg', grams: 200, state: 'cooked' }), foodEnv());
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.dish, 'Steamed rice');
    assert.equal(result.totals.kcal, 260);
    assert.equal(result.totals.carbs, 56);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('photo analysis maps Gemini quota errors to a friendly busy response', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 429 });
  try {
    const response = await worker.fetch(foodRequest({ image: 'AAAA', mimeType: 'image/jpeg', grams: 100 }), foodEnv());
    assert.equal(response.status, 503);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
