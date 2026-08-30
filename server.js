// ============================================================
// BRAIN AFRICA LABS
// MARKETING BRAIN SERVER
// TikTok OAuth 2.0
// ============================================================

const express = require('express');
const crypto = require('crypto');

const config = require('./src/config');

const {
  buildAuthorizeUrl,
  exchangeCodeForToken,
  refreshAccessToken,
  getCreatorInfo
} = require('./src/tiktok');

const {
  createOAuthState,
  verifyOAuthState
} = require('./src/crypto');

const {
  upsertTikTokAccount
} = require('./src/supabase');

const app = express();

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// SECURITY / HELPERS
// ============================================================

function safeErrorMessage(error) {
  return (
    error?.data?.error?.message ||
    error?.data?.message ||
    error?.message ||
    'Unknown error'
  );
}

function redirectToFrontend(path, params = {}) {
  const url = new URL(
    path,
    `${config.frontendUrl}/`
  );

  for (const [key, value] of Object.entries(params)) {
    if (
      value !== undefined &&
      value !== null &&
      value !== ''
    ) {
      url.searchParams.set(key, String(value));
    }
  }

  return url.toString();
}

// ============================================================
// HEALTH
// ============================================================

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'marketing-brain-tiktok-oauth',
    timestamp: new Date().toISOString()
  });
});

// ============================================================
// ROOT
// ============================================================

app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'Brain Africa Labs — Marketing Brain Server',
    version: '1.2.0',
    environment: config.nodeEnv,
    port: config.port
  });
});

// ============================================================
// TIKTOK AUTHORIZE
// ============================================================
//
// Frontend:
// https://brainafricalabs.com/connect-tiktok.html
//
// redirects to:
// https://oauth.brainafricalabs.com/tiktok/authorize
//
// Then:
// Brain Africa Labs → TikTok OAuth
// ============================================================

app.get('/tiktok/authorize', async (req, res) => {
  try {
    const accountId =
      Number(
        req.query.account_id ||
        config.defaultAccountId
      );

    if (
      !Number.isInteger(accountId) ||
      accountId <= 0
    ) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_account_id'
      });
    }

    // --------------------------------------------------------
    // STATE
    // --------------------------------------------------------

    const state = createOAuthState({
      accountId
    });

    const authorizeUrl =
      buildAuthorizeUrl({
        state
      });

    console.log(
      `[TikTok OAuth] Authorize requested for account ${accountId}`
    );

    return res.redirect(302, authorizeUrl);

  } catch (error) {

    console.error(
      '[TikTok OAuth] /authorize error:',
      error
    );

    return res.status(500).json({
      ok: false,
      error: 'tiktok_authorize_failed',
      message: safeErrorMessage(error)
    });
  }
});

// ============================================================
// COMPATIBILITY ROUTE
// ============================================================
//
// Ancienne URL : /tiktok/oauth
//
// On la conserve afin de ne pas casser d'anciens liens.
// ============================================================

app.get('/tiktok/oauth', (req, res) => {
  const accountId =
    Number(
      req.query.account_id ||
      config.defaultAccountId
    );

  const state = createOAuthState({
    accountId
  });

  const authorizeUrl =
    buildAuthorizeUrl({
      state
    });

  return res.redirect(302, authorizeUrl);
});

// ============================================================
// TIKTOK CALLBACK
// ============================================================

app.get('/tiktok/callback', async (req, res) => {

  const {
    code,
    state,
    error,
    error_description
  } = req.query;

  // ----------------------------------------------------------
  // TikTok OAuth ERROR
  // ----------------------------------------------------------

  if (error) {

    console.error(
      '[TikTok OAuth] TikTok returned error:',
      error,
      error_description || ''
    );

    return res.redirect(
      redirectToFrontend(
        '/connect-tiktok.html',
        {
          tiktok: 'error',
          error,
          error_description:
            error_description || ''
        }
      )
    );
  }

  // ----------------------------------------------------------
  // REQUIRED PARAMETERS
  // ----------------------------------------------------------

  if (!code) {

    return res.status(400).json({
      ok: false,
      error: 'missing_authorization_code'
    });
  }

  if (!state) {

    return res.status(400).json({
      ok: false,
      error: 'missing_oauth_state'
    });
  }

  // ----------------------------------------------------------
  // VERIFY STATE
  // ----------------------------------------------------------

  let stateData;

  try {

    stateData =
      verifyOAuthState(state);

  } catch (error) {

    console.error(
      '[TikTok OAuth] Invalid state:',
      error.message
    );

    return res.status(400).json({
      ok: false,
      error: 'invalid_oauth_state'
    });
  }

  const accountId =
    Number(
      stateData.accountId ||
      config.defaultAccountId
    );

  if (
    !Number.isInteger(accountId) ||
    accountId <= 0
  ) {

    return res.status(400).json({
      ok: false,
      error: 'invalid_account_id'
    });
  }

  // ----------------------------------------------------------
  // EXCHANGE CODE
  // ----------------------------------------------------------

  try {

    console.log(
      `[TikTok OAuth] Exchanging authorization code for account ${accountId}`
    );

    const token =
      await exchangeCodeForToken(code);

    // --------------------------------------------------------
    // CREATOR INFO
    // --------------------------------------------------------

    let creatorInfo = null;

    try {

      creatorInfo =
        await getCreatorInfo(
          token.access_token
        );

    } catch (creatorError) {

      console.error(
        '[TikTok OAuth] Creator Info failed:',
        creatorError
      );

      // Creator Info failure should not necessarily destroy
      // the OAuth connection if TikTok already returned tokens.
      creatorInfo = null;
    }

    const creator =
      creatorInfo?.data || {};

    // --------------------------------------------------------
    // ACCOUNT DATA
    // --------------------------------------------------------

    const accountData = {

      id: accountId,

      platform: 'tiktok',

      account_name:
        creator.creator_nickname ||
        null,

      open_id:
        token.open_id ||
        null,

      access_token:
        token.access_token,

      refresh_token:
        token.refresh_token ||
        null,

      token_type:
        token.token_type ||
        'Bearer',

      scope:
        token.scope ||
        null,

      expires_in:
        token.expires_in ??
        null,

      refresh_expires_in:
        token.refresh_expires_in ??
        null,

      creator_username:
        creator.creator_username ||
        null,

      creator_nickname:
        creator.creator_nickname ||
        null,

      creator_avatar_url:
        creator.creator_avatar_url ||
        null,

      updated_at:
        new Date().toISOString()
    };

    // --------------------------------------------------------
    // SUPABASE
    // --------------------------------------------------------

    await upsertTikTokAccount(
      accountData
    );

    console.log(
      `[TikTok OAuth] Account ${accountId} successfully connected`
    );

    // --------------------------------------------------------
    // FRONTEND SUCCESS
    // --------------------------------------------------------

    return res.redirect(
      redirectToFrontend(
        '/connect-tiktok.html',
        {
          tiktok: 'connected',
          account_id: accountId,
          open_id: token.open_id
        }
      )
    );

  } catch (error) {

    console.error(
      '[TikTok OAuth] Callback failed:',
      error
    );

    return res.redirect(
      redirectToFrontend(
        '/connect-tiktok.html',
        {
          tiktok: 'error',
          error: 'oauth_callback_failed'
        }
      )
    );
  }
});

// ============================================================
// 404
// ============================================================

app.use((req, res) => {

  res.status(404).json({
    ok: false,
    error: 'not_found',
    path: req.path
  });
});

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use((error, req, res, next) => {

  console.error(
    '[Server Error]',
    error
  );

  res.status(
    error.status || 500
  ).json({
    ok: false,
    error: 'internal_server_error',
    message: safeErrorMessage(error)
  });
});

// ============================================================
// START
// ============================================================

app.listen(
  config.port,
  () => {

    console.log(
      '=================================================='
    );

    console.log(
      'Brain Africa Labs — Marketing Brain Server'
    );

    console.log(
      'Version: 1.2.0'
    );

    console.log(
      `Environment: ${config.nodeEnv}`
    );

    console.log(
      `Port: ${config.port}`
    );

    console.log(
      `Public URL: ${config.serverPublicUrl}`
    );

    console.log(
      `Frontend URL: ${config.frontendUrl}`
    );

    console.log(
      `TikTok redirect: ${config.tiktok.redirectUri}`
    );

    console.log(
      `TikTok scopes: ${config.tiktok.scopes.join(',')}`
    );

    console.log(
      `Default account ID: ${config.defaultAccountId}`
    );

    console.log(
      'TikTok routes:'
    );

    console.log(
      '  GET /tiktok/authorize'
    );

    console.log(
      '  GET /tiktok/oauth'
    );

    console.log(
      '  GET /tiktok/callback'
    );

    console.log(
      '  GET /health'
    );

    console.log(
      '=================================================='
    );
  }
);

module.exports = app;
