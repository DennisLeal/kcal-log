const MAX_REQUEST_BYTES = 20000;
const MAX_PAYLOAD_BYTES = 12000;
const MAX_CLOCK_SKEW_SECONDS = 300;

function doPost(event) {
  const body = event && event.postData && event.postData.contents;
  if (typeof body !== 'string' ||
      Utilities.newBlob(body).getBytes().length > MAX_REQUEST_BYTES) {
    return jsonResponse({ ok: false, error: 'invalid request' });
  }

  let request;
  try {
    request = JSON.parse(body);
  } catch (error) {
    return jsonResponse({ ok: false, error: 'invalid request' });
  }
  if (!request ||
      Object.prototype.toString.call(request) !== '[object Object]' ||
      Object.keys(request).some(function (key) {
        return key !== 'timestamp' &&
          key !== 'nonce' &&
          key !== 'payload' &&
          key !== 'signature';
      })) {
    return jsonResponse({ ok: false, error: 'invalid request' });
  }

  const timestamp = request.timestamp;
  const nonce = request.nonce;
  const payloadJson = request.payload;
  const signature = request.signature;
  if (!Number.isSafeInteger(timestamp) ||
      Math.abs(Math.floor(Date.now() / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS ||
      typeof nonce !== 'string' ||
      !/^[A-Za-z0-9_-]{24,64}$/.test(nonce) ||
      typeof payloadJson !== 'string' ||
      Utilities.newBlob(payloadJson).getBytes().length > MAX_PAYLOAD_BYTES ||
      typeof signature !== 'string' ||
      !/^[a-f0-9]{64}$/.test(signature)) {
    return jsonResponse({ ok: false, error: 'invalid request' });
  }

  const secret = PropertiesService.getScriptProperties()
    .getProperty('EMAIL_RELAY_HMAC_SECRET');
  if (typeof secret !== 'string' || secret.length < 32) {
    console.error('Email relay secret is not configured.');
    return jsonResponse({ ok: false, error: 'relay unavailable' });
  }

  const expectedSignature = hmacHex(
    timestamp + '\n' + nonce + '\n' + payloadJson,
    secret
  );
  if (!constantTimeEqual(signature, expectedSignature)) {
    return jsonResponse({ ok: false, error: 'invalid request' });
  }

  let payload;
  try {
    payload = JSON.parse(payloadJson);
  } catch (error) {
    return jsonResponse({ ok: false, error: 'invalid email' });
  }
  if (!isValidEmailPayload(payload)) {
    return jsonResponse({ ok: false, error: 'invalid email' });
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    return jsonResponse({ ok: false, error: 'please retry' });
  }

  try {
    const properties = PropertiesService.getScriptProperties();
    const noncePrefix = 'EMAIL_RELAY_NONCE_';
    const nonceKey = noncePrefix + nonce;
    const currentTime = Date.now();
    const nonceExpiry = currentTime - (MAX_CLOCK_SKEW_SECONDS * 2 + 1) * 1000;
    const storedProperties = properties.getProperties();
    Object.keys(storedProperties).forEach(function (key) {
      if (key.indexOf(noncePrefix) === 0 &&
          Number(storedProperties[key]) < nonceExpiry) {
        properties.deleteProperty(key);
      }
    });
    if (properties.getProperty(nonceKey)) {
      return jsonResponse({ ok: false, error: 'request already used' });
    }
    properties.setProperty(nonceKey, String(currentTime));
  } finally {
    lock.releaseLock();
  }

  try {
    MailApp.sendEmail({
      to: payload.to,
      subject: payload.subject,
      body: payload.text
    });
  } catch (error) {
    console.error('Email relay delivery failed.');
    return jsonResponse({ ok: false, error: 'email delivery failed' });
  }

  return jsonResponse({ ok: true });
}

function hmacHex(message, secret) {
  const bytes = Utilities.computeHmacSha256Signature(message, secret);
  return bytes.map(function (byte) {
    return ('0' + ((byte + 256) % 256).toString(16)).slice(-2);
  }).join('');
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function isValidEmailPayload(payload) {
  if (!payload || Object.prototype.toString.call(payload) !== '[object Object]') {
    return false;
  }
  if (Object.keys(payload).some(function (key) {
    return key !== 'to' && key !== 'subject' && key !== 'text';
  })) {
    return false;
  }

  return typeof payload.to === 'string' &&
    payload.to.length <= 254 &&
    /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/.test(payload.to) &&
    typeof payload.subject === 'string' &&
    payload.subject.length > 0 &&
    payload.subject.length <= 200 &&
    !/[\r\n]/.test(payload.subject) &&
    typeof payload.text === 'string' &&
    payload.text.length > 0 &&
    payload.text.length <= 10000;
}

function jsonResponse(value) {
  return ContentService.createTextOutput(JSON.stringify(value))
    .setMimeType(ContentService.MimeType.JSON);
}
