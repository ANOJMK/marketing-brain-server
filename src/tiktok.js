// ============================================================
// BRAIN AFRICA LABS
// MARKETING BRAIN SERVER
//
// TikTok API
// OAuth 2.0
// Login Kit
// Content Posting API
//
// VERSION: 1.1.0
// ============================================================

const config = require('./config');


// ============================================================
// TIKTOK ENDPOINTS
// ============================================================

const TIKTOK_AUTHORIZE_URL =
  'https://www.tiktok.com/v2/auth/authorize/';

const TIKTOK_TOKEN_URL =
  'https://open.tiktokapis.com/v2/oauth/token/';

const TIKTOK_CREATOR_INFO_URL =
  'https://open.tiktokapis.com/v2/post/publish/creator_info/query/';

const TIKTOK_STATUS_URL =
  'https://open.tiktokapis.com/v2/post/publish/status/fetch/';


// ============================================================
// INTERNAL HELPERS
// ============================================================

/**
 * Safely parse TikTok HTTP response.
 *
 * TikTok normally returns JSON, but this prevents the backend
 * from crashing if an intermediary/proxy returns HTML or text.
 */
async function parseResponse(response) {

  const contentType =
    response.headers.get(
      'content-type'
    ) || '';

  const text =
    await response.text();

  if (!text) {
    return {};
  }

  if (
    contentType.includes(
      'application/json'
    )
  ) {

    try {

      return JSON.parse(text);

    } catch {

      return {
        raw:
          text
      };
    }
  }

  try {

    return JSON.parse(text);

  } catch {

    return {
      raw:
        text
    };
  }
}


/**
 * Build a standardized TikTok API error.
 */
function createTikTokError(
  message,
  response,
  data
) {

  const error =
    new Error(message);

  error.status =
    response?.status || 500;

  error.data =
    data || null;

  return error;
}


/**
 * TikTok sometimes returns HTTP 200 with an error object.
 *
 * Example:
 *
 * {
 *   "error": {
 *      "code": "scope_not_authorized",
 *      "message": "..."
 *   }
 * }
 */
function assertTikTokSuccess(
  data,
  message
) {

  const errorCode =
    data?.error?.code;

  if (
    errorCode &&
    errorCode !== 'ok'
  ) {

    const error =
      new Error(
        message
      );

    error.status =
      400;

    error.data =
      data;

    throw error;
  }
}


// ============================================================
// BUILD TIKTOK AUTHORIZATION URL
// ============================================================
//
// Web OAuth flow:
//
// Brain Africa Labs
//       ↓
// /tiktok/authorize
//       ↓
// TikTok OAuth
//
// TikTok Web OAuth requires:
// - client_key
// - response_type=code
// - scope
// - redirect_uri
// - state
//
// PKCE is NOT required for the Web flow.
// ============================================================

function buildAuthorizeUrl({
  state
}) {

  if (
    !config.tiktok.clientKey
  ) {

    throw new Error(
      'TikTok client key is missing.'
    );
  }


  if (
    !config.tiktok.redirectUri
  ) {

    throw new Error(
      'TikTok redirect URI is missing.'
    );
  }


  if (
    !Array.isArray(
      config.tiktok.scopes
    ) ||
    config.tiktok.scopes.length === 0
  ) {

    throw new Error(
      'TikTok scopes are missing.'
    );
  }


  if (!state) {

    throw new Error(
      'TikTok OAuth state is required.'
    );
  }


  const params =
    new URLSearchParams();


  // ----------------------------------------------------------
  // Client
  // ----------------------------------------------------------

  params.set(
    'client_key',
    config.tiktok.clientKey
  );


  // ----------------------------------------------------------
  // Authorization code flow
  // ----------------------------------------------------------

  params.set(
    'response_type',
    'code'
  );


  // ----------------------------------------------------------
  // Scopes
  //
  // TikTok expects a comma-separated scope string.
  // ----------------------------------------------------------

  params.set(
    'scope',
    config.tiktok.scopes.join(',')
  );


  // ----------------------------------------------------------
  // Registered redirect URI
  // ----------------------------------------------------------

  params.set(
    'redirect_uri',
    config.tiktok.redirectUri
  );


  // ----------------------------------------------------------
  // Anti-CSRF state
  // ----------------------------------------------------------

  params.set(
    'state',
    state
  );


  return (
    `${TIKTOK_AUTHORIZE_URL}?` +
    params.toString()
  );
}


// ============================================================
// EXCHANGE AUTHORIZATION CODE FOR TOKENS
// ============================================================
//
// POST:
//
// https://open.tiktokapis.com/v2/oauth/token/
//
// TikTok requires:
//
// client_key
// client_secret
// code
// grant_type=authorization_code
// redirect_uri
//
// The access token and refresh token MUST remain server-side.
// ============================================================

async function exchangeCodeForToken(
  code
) {

  if (!code) {

    throw new Error(
      'TikTok authorization code is missing.'
    );
  }


  if (
    !config.tiktok.clientKey
  ) {

    throw new Error(
      'TikTok client key is missing.'
    );
  }


  if (
    !config.tiktok.clientSecret
  ) {

    throw new Error(
      'TikTok client secret is missing.'
    );
  }


  if (
    !config.tiktok.redirectUri
  ) {

    throw new Error(
      'TikTok redirect URI is missing.'
    );
  }


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


  // IMPORTANT:
  //
  // This MUST exactly match the redirect URI used
  // during authorization.
  //

  body.set(
    'redirect_uri',
    config.tiktok.redirectUri
  );


  const response =
    await fetch(
      TIKTOK_TOKEN_URL,
      {

        method:
          'POST',

        headers: {

          'Content-Type':
            'application/x-www-form-urlencoded',

          'Cache-Control':
            'no-cache',

          'Accept':
            'application/json'
        },

        body
      }
    );


  const data =
    await parseResponse(
      response
    );


  if (!response.ok) {

    throw createTikTokError(
      'TikTok token exchange failed.',
      response,
      data
    );
  }


  // ----------------------------------------------------------
  // TikTok can return HTTP 200 + error object.
  // ----------------------------------------------------------

  assertTikTokSuccess(
    data,
    'TikTok token exchange returned an error.'
  );


  // ----------------------------------------------------------
  // Validate token response
  // ----------------------------------------------------------

  if (
    !data.access_token ||
    !data.open_id
  ) {

    const error =
      new Error(
        'TikTok token response incomplete.'
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }


  // ----------------------------------------------------------
  // Return full token response to the SERVER only.
  //
  // server.js stores it in Supabase.
  //
  // NEVER send this object directly to browser.
  // ----------------------------------------------------------

  return {

    access_token:
      data.access_token,

    refresh_token:
      data.refresh_token ||
      null,

    open_id:
      data.open_id,

    scope:
      data.scope ||
      null,

    expires_in:
      data.expires_in ||
      null,

    refresh_expires_in:
      data.refresh_expires_in ||
      null,

    token_type:
      data.token_type ||
      'Bearer'
  };
}


// ============================================================
// REFRESH ACCESS TOKEN
// ============================================================
//
// TikTok access tokens expire after a limited period.
// Refresh token must therefore be persisted server-side.
//
// ============================================================

async function refreshAccessToken(
  refreshToken
) {

  if (!refreshToken) {

    throw new Error(
      'TikTok refresh token is missing.'
    );
  }


  if (
    !config.tiktok.clientKey
  ) {

    throw new Error(
      'TikTok client key is missing.'
    );
  }


  if (
    !config.tiktok.clientSecret
  ) {

    throw new Error(
      'TikTok client secret is missing.'
    );
  }


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

        method:
          'POST',

        headers: {

          'Content-Type':
            'application/x-www-form-urlencoded',

          'Cache-Control':
            'no-cache',

          'Accept':
            'application/json'
        },

        body
      }
    );


  const data =
    await parseResponse(
      response
    );


  if (!response.ok) {

    throw createTikTokError(
      'TikTok token refresh failed.',
      response,
      data
    );
  }


  assertTikTokSuccess(
    data,
    'TikTok token refresh returned an error.'
  );


  if (
    !data.access_token ||
    !data.open_id
  ) {

    const error =
      new Error(
        'TikTok refresh response incomplete.'
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }


  return {

    access_token:
      data.access_token,

    refresh_token:
      data.refresh_token ||
      null,

    open_id:
      data.open_id,

    scope:
      data.scope ||
      null,

    expires_in:
      data.expires_in ||
      null,

    refresh_expires_in:
      data.refresh_expires_in ||
      null,

    token_type:
      data.token_type ||
      'Bearer'
  };
}


// ============================================================
// QUERY CREATOR INFO
// ============================================================
//
// Endpoint:
//
// POST
// /v2/post/publish/creator_info/query/
//
// Scope:
// video.publish
//
// TikTok requires this before rendering the Export/Publish UI.
// It provides the actual creator privacy options and interaction
// settings.
//
// ============================================================

async function getCreatorInfo(
  accessToken
) {

  if (!accessToken) {

    throw new Error(
      'TikTok access token is missing.'
    );
  }


  const response =
    await fetch(
      TIKTOK_CREATOR_INFO_URL,
      {

        method:
          'POST',

        headers: {

          'Authorization':
            `Bearer ${accessToken}`,

          'Content-Type':
            'application/json; charset=UTF-8',

          'Accept':
            'application/json'
        },

        body:
          JSON.stringify({})
      }
    );


  const data =
    await parseResponse(
      response
    );


  if (!response.ok) {

    throw createTikTokError(
      'TikTok Creator Info request failed.',
      response,
      data
    );
  }


  assertTikTokSuccess(
    data,
    'TikTok Creator Info returned an error.'
  );


  return data;
}


// ============================================================
// GET PUBLISH STATUS
// ============================================================
//
// Endpoint:
//
// POST
// /v2/post/publish/status/fetch/
//
// Scope:
// video.publish / video.upload
//
// ============================================================

async function getPublishStatus(
  accessToken,
  publishId
) {

  if (!accessToken) {

    throw new Error(
      'TikTok access token is missing.'
    );
  }


  if (!publishId) {

    throw new Error(
      'TikTok publish_id is missing.'
    );
  }


  const response =
    await fetch(
      TIKTOK_STATUS_URL,
      {

        method:
          'POST',

        headers: {

          'Authorization':
            `Bearer ${accessToken}`,

          'Content-Type':
            'application/json; charset=UTF-8',

          'Accept':
            'application/json'
        },

        body:
          JSON.stringify({

            publish_id:
              publishId

          })
      }
    );


  const data =
    await parseResponse(
      response
    );


  if (!response.ok) {

    throw createTikTokError(
      'TikTok publish status request failed.',
      response,
      data
    );
  }


  assertTikTokSuccess(
    data,
    'TikTok publish status returned an error.'
  );


  return data;
}


// ============================================================
// EXPORTS
// ============================================================

module.exports = {

  buildAuthorizeUrl,

  exchangeCodeForToken,

  refreshAccessToken,

  getCreatorInfo,

  getPublishStatus
};
