import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import worker, {
  checkRateLimit,
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
