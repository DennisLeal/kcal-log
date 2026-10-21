import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import test from 'node:test';

const scriptSource = await readFile(new URL('./Code.gs', import.meta.url), 'utf8');

function createRelay({ secret = 'a'.repeat(64), now = Date.now() } = {}) {
  const scriptProperties = new Map([['EMAIL_RELAY_HMAC_SECRET', secret]]);
  const sentEmails = [];
  const context = vm.createContext({
    console: { error() {} },
    Date: class extends Date {
      static now() {
        return now;
      }
    },
    PropertiesService: {
      getScriptProperties: () => ({
        getProperty: key => scriptProperties.get(key) || null,
        getProperties: () => Object.fromEntries(scriptProperties),
        setProperty: (key, value) => scriptProperties.set(key, value),
        deleteProperty: key => scriptProperties.delete(key)
      })
    },
    LockService: {
      getScriptLock: () => ({
        tryLock: () => true,
        releaseLock() {}
      })
    },
    MailApp: {
      sendEmail: message => sentEmails.push(message)
    },
    Utilities: {
      newBlob(value) {
        return {
          getBytes: () => Array.from(new TextEncoder().encode(value))
        };
      },
      computeHmacSha256Signature(message, key) {
        return Array.from(
          createHmac('sha256', key).update(message).digest(),
          byte => byte > 127 ? byte - 256 : byte
        );
      }
    },
    ContentService: {
      MimeType: { JSON: 'application/json' },
      createTextOutput(content) {
        return {
          content,
          setMimeType(type) {
            this.mimeType = type;
            return this;
          }
        };
      }
    }
  });
  context.TextEncoder = TextEncoder;
  vm.runInContext(scriptSource, context);

  function request(payload, options = {}) {
    const timestamp = options.timestamp ?? Math.floor(now / 1000);
    const nonce = options.nonce ?? 'n'.repeat(24);
    const payloadJson = JSON.stringify(payload);
    const computedSignature = createHmac('sha256', secret)
      .update(`${timestamp}\n${nonce}\n${payloadJson}`)
      .digest('hex');
    const envelope = {
      timestamp,
      nonce,
      payload: payloadJson,
      signature: options.signature ?? computedSignature
    };
    return context.doPost({ postData: { contents: JSON.stringify(envelope) } });
  }

  return { context, request, scriptProperties, sentEmails };
}

test('authenticated email relay delivers only one validated recipient', () => {
  const relay = createRelay();
  const response = relay.request({
    to: 'buyer@example.com',
    subject: 'Purchase confirmed',
    text: 'Your access code is ABC123.'
  });

  assert.deepEqual(JSON.parse(response.content), { ok: true });
  assert.equal(response.mimeType, 'application/json');
  assert.deepEqual(JSON.parse(JSON.stringify(relay.sentEmails)), [{
    to: 'buyer@example.com',
    subject: 'Purchase confirmed',
    body: 'Your access code is ABC123.'
  }]);
  assert.equal(
    [...relay.scriptProperties.keys()].filter(key => key.startsWith('EMAIL_RELAY_NONCE_')).length,
    1
  );
});

test('relay rejects invalid signatures and stale requests without sending email', () => {
  const relay = createRelay();
  const invalidSignature = relay.request(
    { to: 'buyer@example.com', subject: 'Notice', text: 'Message' },
    { signature: '0'.repeat(64) }
  );
  assert.equal(JSON.parse(invalidSignature.content).ok, false);

  const staleResponse = relay.request(
    { to: 'buyer@example.com', subject: 'Notice', text: 'Message' },
    { timestamp: Math.floor(Date.now() / 1000) - 301, nonce: 's'.repeat(24) }
  );

  assert.equal(JSON.parse(staleResponse.content).ok, false);
  assert.equal(relay.sentEmails.length, 0);
});

test('relay rejects replayed nonces and malformed or multi-recipient payloads', () => {
  const relay = createRelay();
  const message = {
    to: 'buyer@example.com',
    subject: 'Notice',
    text: 'Message'
  };
  assert.equal(JSON.parse(relay.request(message).content).ok, true);
  assert.equal(JSON.parse(relay.request(message).content).ok, false);
  assert.equal(JSON.parse(relay.request({
    to: 'buyer@example.com,attacker@example.com',
    subject: 'Notice',
    text: 'Message'
  }, { nonce: 'm'.repeat(24) }).content).ok, false);
  assert.equal(relay.sentEmails.length, 1);
});
