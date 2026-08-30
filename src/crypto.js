// ============================================================
// BRAIN AFRICA LABS
// OAUTH CRYPTO
// ============================================================

const crypto = require('crypto');

function base64url(buffer) {
  return Buffer
    .from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function randomToken(bytes = 32) {
  return base64url(
    crypto.randomBytes(bytes)
  );
}

function signPayload(payload, secret) {

  const encoded = base64url(
    Buffer.from(
      JSON.stringify(payload),
      'utf8'
    )
  );

  const signature =
    crypto
      .createHmac(
        'sha256',
        secret
      )
      .update(encoded)
      .digest();

  return `${encoded}.${base64url(signature)}`;
}

function verifyPayload(token, secret) {

  if (!token || !token.includes('.')) {
    return null;
  }

  const [encoded, signature] =
    token.split('.');

  if (!encoded || !signature) {
    return null;
  }

  const expected =
    crypto
      .createHmac(
        'sha256',
        secret
      )
      .update(encoded)
      .digest();

  const received =
    Buffer.from(
      signature
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(
          Math.ceil(signature.length / 4) * 4,
          '='
        ),
      'base64'
    );

  if (
    received.length !== expected.length ||
    !crypto.timingSafeEqual(
      received,
      expected
    )
  ) {
    return null;
  }

  try {

    const json =
      Buffer
        .from(
          encoded
            .replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(
              Math.ceil(encoded.length / 4) * 4,
              '='
            ),
          'base64'
        )
        .toString('utf8');

    return JSON.parse(json);

  } catch {
    return null;
  }
}

module.exports = {
  randomToken,
  signPayload,
  verifyPayload
};
