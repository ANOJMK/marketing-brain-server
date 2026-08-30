// ============================================================
// BRAIN AFRICA LABS
// TIKTOK API
// ============================================================

const config = require('./config');

const TIKTOK_AUTHORIZE_URL =
  'https://www.tiktok.com/v2/auth/authorize/';

const TIKTOK_TOKEN_URL =
  'https://open.tiktokapis.com/v2/oauth/token/';

const TIKTOK_CREATOR_INFO_URL =
  'https://open.tiktokapis.com/v2/post/publish/creator_info/query/';

const TIKTOK_STATUS_URL =
  'https://open.tiktokapis.com/v2/post/publish/status/fetch/';

function buildAuthorizeUrl({
  state
}) {

  const params =
    new URLSearchParams();

  params.set(
    'client_key',
    config.tiktok.clientKey
  );

  params.set(
    'response_type',
    'code'
  );

  params.set(
    'scope',
    config.tiktok.scopes.join(',')
  );

  params.set(
    'redirect_uri',
    config.tiktok.redirectUri
  );

  params.set(
    'state',
    state
  );

  return (
    `${TIKTOK_AUTHORIZE_URL}?` +
    params.toString()
  );
}

async function exchangeCodeForToken(
  code
) {

  const body =
    new URLSearchParams();

  body.set(
    'client_key',
    config.tiktok.clientKey
  );

  body.set(
    'client_secret',
    config.tiktok.clientSecret
  );

  body.set(
    'code',
    code
  );

  body.set(
    'grant_type',
    'authorization_code'
  );

  body.set(
    'redirect_uri',
    config.tiktok.redirectUri
  );

  const response =
    await fetch(
      TIKTOK_TOKEN_URL,
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',

          'Cache-Control':
            'no-cache'
        },

        body
      }
    );

  const data =
    await response.json();

  if (!response.ok) {

    const error =
      new Error(
        'TikTok token exchange failed'
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }

  if (
    !data.access_token ||
    !data.open_id
  ) {

    const error =
      new Error(
        'TikTok token response incomplete'
      );

    error.data =
      data;

    throw error;
  }

  return data;
}

async function refreshAccessToken(
  refreshToken
) {

  const body =
    new URLSearchParams();

  body.set(
    'client_key',
    config.tiktok.clientKey
  );

  body.set(
    'client_secret',
    config.tiktok.clientSecret
  );

  body.set(
    'grant_type',
    'refresh_token'
  );

  body.set(
    'refresh_token',
    refreshToken
  );

  const response =
    await fetch(
      TIKTOK_TOKEN_URL,
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',

          'Cache-Control':
            'no-cache'
        },

        body
      }
    );

  const data =
    await response.json();

  if (!response.ok) {

    const error =
      new Error(
        'TikTok token refresh failed'
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }

  return data;
}

async function getCreatorInfo(
  accessToken
) {

  const response =
    await fetch(
      TIKTOK_CREATOR_INFO_URL,
      {
        method: 'POST',

        headers: {
          Authorization:
            `Bearer ${accessToken}`,

          'Content-Type':
            'application/json; charset=UTF-8'
        },

        body:
          JSON.stringify({})
      }
    );

  const data =
    await response.json();

  if (!response.ok) {

    const error =
      new Error(
        'TikTok Creator Info failed'
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }

  return data;
}

async function getPublishStatus(
  accessToken,
  publishId
) {

  const response =
    await fetch(
      TIKTOK_STATUS_URL,
      {
        method: 'POST',

        headers: {
          Authorization:
            `Bearer ${accessToken}`,

          'Content-Type':
            'application/json; charset=UTF-8'
        },

        body:
          JSON.stringify({
            publish_id:
              publishId
          })
      }
    );

  const data =
    await response.json();

  if (!response.ok) {

    const error =
      new Error(
        'TikTok publish status failed'
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }

  return data;
}

module.exports = {
  buildAuthorizeUrl,
  exchangeCodeForToken,
  refreshAccessToken,
  getCreatorInfo,
  getPublishStatus
};
