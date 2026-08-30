// ============================================================
// BRAIN AFRICA LABS
// MARKETING BRAIN SERVER
//
// TikTok OAuth 2.0
// TikTok Creator Info
// TikTok Publish Status
// Supabase persistence
// ============================================================

const express =
  require('express');

const cors =
  require('cors');

const cookieParser =
  require('cookie-parser');

const config =
  require('./src/config');

const {
  randomToken,
  signPayload,
  verifyPayload
} =
  require('./src/crypto');

const {
  buildAuthorizeUrl,
  exchangeCodeForToken,
  refreshAccessToken,
  getCreatorInfo,
  getPublishStatus
} =
  require('./src/tiktok');

const {
  saveTikTokAccount,
  getTikTokAccountByOpenId
} =
  require('./src/supabase');

const app =
  express();

app.set(
  'trust proxy',
  1
);

app.disable(
  'x-powered-by'
);

app.use(
  express.json({
    limit: '2mb'
  })
);

app.use(
  express.urlencoded({
    extended: false
  })
);

app.use(
  cors({
    origin:
      config.frontendUrl,

    credentials:
      true
  })
);

app.use(
  cookieParser()
);

// ============================================================
// HELPERS
// ============================================================

function safeReturnTo(value) {

  const fallback =
    '/connect-tiktok.html';

  if (!value) {
    return fallback;
  }

  try {

    const url =
      new URL(
        value,
        config.frontendUrl
      );

    const allowedHost =
      new URL(
        config.frontendUrl
      ).hostname;

    if (
      url.hostname !==
      allowedHost
    ) {
      return fallback;
    }

    return (
      url.pathname +
      url.search
    );

  } catch {

    if (
      String(value)
        .startsWith('/')
    ) {
      return String(value);
    }

    return fallback;
  }
}

function frontendRedirect(
  path,
  params = {}
) {

  const base =
    new URL(
      config.frontendUrl
    );

  base.pathname =
    path.startsWith('/')
      ? path
      : `/${path}`;

  for (
    const [key, value]
    of Object.entries(params)
  ) {

    if (
      value !== undefined &&
      value !== null
    ) {

      base.searchParams.set(
        key,
        String(value)
      );
    }
  }

  return base.toString();
}

function cookieOptions() {

  return {
    httpOnly: true,

    secure:
      config.nodeEnv ===
      'production',

    sameSite: 'lax',

    maxAge:
      10 * 60 * 1000,

    path: '/'
  };
}

function publicAccountResponse(
  account
) {

  if (!account) {
    return null;
  }

  return {
    account_id:
      account.account_id,

    open_id:
      account.open_id,

    display_name:
      account.display_name || null,

    avatar_url:
      account.avatar_url || null,

    scope:
      account.scope || null,

    expires_at:
      account.expires_at || null,

    refresh_expires_at:
      account.refresh_expires_at || null,

    token_type:
      account.token_type || 'Bearer',

    connected:
      true
  };
}

// ============================================================
// HEALTH
// ============================================================

app.get(
  '/',
  (req, res) => {

    res.json({
      ok: true,

      service:
        'Brain Africa Labs Marketing Brain Server',

      version:
        '1.0.0',

      environment:
        config.nodeEnv,

      timestamp:
        new Date().toISOString()
    });
  }
);

app.get(
  '/health',
  (req, res) => {

    res.json({
      ok: true,

      service:
        'marketing-brain-server',

      tiktok:
        true,

      supabase:
        true,

      timestamp:
        new Date().toISOString()
    });
  }
);

// ============================================================
// TIKTOK AUTHORIZE
// ============================================================
//
// Frontend:
// https://oauth.brainafricalabs.com/tiktok/authorize
//
// Optional:
// ?return_to=/connect-tiktok.html
// ?campaign_id=123
//
// ============================================================

app.get(
  '/tiktok/authorize',
  (req, res) => {

    try {

      const returnTo =
        safeReturnTo(
          req.query.return_to
        );

      const campaignId =
        req.query.campaign_id ||
        null;

      const nonce =
        randomToken(32);

      const payload = {

        nonce,

        return_to:
          returnTo,

        campaign_id:
          campaignId,

        created_at:
          Date.now()
      };

      const state =
        signPayload(
          payload,
          config.security
            .oauthStateSecret
        );

      res.cookie(
        'tiktok_oauth_nonce',
        nonce,
        cookieOptions()
      );

      const authorizeUrl =
        buildAuthorizeUrl({
          state
        });

      console.log(
        '[TikTok OAuth] Redirecting user to TikTok'
      );

      res.redirect(
        authorizeUrl
      );

    } catch (error) {

      console.error(
        '[TikTok OAuth] authorize error:',
        error
      );

      res.status(500).send(
        `
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>TikTok Authorization Error</title>
        </head>
        <body>
          <h1>TikTok Authorization Error</h1>
          <p>Unable to start TikTok authorization.</p>
        </body>
        </html>
        `
      );
    }
  }
);

// ============================================================
// TIKTOK CALLBACK
// ============================================================

app.get(
  '/tiktok/callback',
  async (req, res) => {

    const {
      code,
      state,
      error,
      error_description
    } = req.query;

    console.log(
      '[TikTok OAuth] Callback received'
    );

    // --------------------------------------------------------
    // TikTok returned an error
    // --------------------------------------------------------

    if (error) {

      console.error(
        '[TikTok OAuth] TikTok error:',
        error,
        error_description
      );

      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {
            tiktok:
              'error',

            error:
              error,

            error_description:
              error_description ||
              'TikTok authorization failed.'
          }
        )
      );
    }

    // --------------------------------------------------------
    // Missing code/state
    // --------------------------------------------------------

    if (!code || !state) {

      return res.status(400).send(
        'TikTok callback incomplete: code/state missing.'
      );
    }

    // --------------------------------------------------------
    // Verify signed state
    // --------------------------------------------------------

    const stateData =
      verifyPayload(
        state,
        config.security
          .oauthStateSecret
      );

    if (!stateData) {

      console.error(
        '[TikTok OAuth] Invalid state signature'
      );

      return res.status(403).send(
        'Invalid OAuth state.'
      );
    }

    // --------------------------------------------------------
    // Verify expiration
    // --------------------------------------------------------

    const age =
      Date.now() -
      Number(
        stateData.created_at || 0
      );

    if (
      !Number.isFinite(age) ||
      age < 0 ||
      age >
        10 * 60 * 1000
    ) {

      return res.status(403).send(
        'OAuth state expired.'
      );
    }

    // --------------------------------------------------------
    // Verify nonce cookie
    // --------------------------------------------------------

    const cookieNonce =
      req.cookies
        ?.tiktok_oauth_nonce;

    if (
      !cookieNonce ||
      cookieNonce !==
        stateData.nonce
    ) {

      console.error(
        '[TikTok OAuth] State nonce mismatch'
      );

      return res.status(403).send(
        'OAuth state validation failed.'
      );
    }

    // Delete OAuth cookie
    res.clearCookie(
      'tiktok_oauth_nonce',
      {
        httpOnly: true,
        secure:
          config.nodeEnv ===
          'production',
        sameSite: 'lax',
        path: '/'
      }
    );

    // --------------------------------------------------------
    // Exchange authorization code
    // --------------------------------------------------------

    try {

      const token =
        await exchangeCodeForToken(
          code
        );

      console.log(
        '[TikTok OAuth] Token exchange successful'
      );

      // ------------------------------------------------------
      // Calculate expiration dates
      // ------------------------------------------------------

      const now =
        Date.now();

      const expiresAt =
        token.expires_in
          ? new Date(
              now +
              Number(
                token.expires_in
              ) *
              1000
            ).toISOString()
          : null;

      const refreshExpiresAt =
        token.refresh_expires_in
          ? new Date(
              now +
              Number(
                token.refresh_expires_in
              ) *
              1000
            ).toISOString()
          : null;

      // ------------------------------------------------------
      // Save account
      // ------------------------------------------------------

      const account = {

        account_id:
          config.defaultAccountId,

        open_id:
          token.open_id,

        access_token:
          token.access_token,

        refresh_token:
          token.refresh_token,

        token_type:
          token.token_type ||
          'Bearer',

        scope:
          token.scope ||
          null,

        expires_at:
          expiresAt,

        refresh_expires_at:
          refreshExpiresAt,

        connected_at:
          new Date()
            .toISOString(),

        updated_at:
          new Date()
            .toISOString()
      };

      try {

        await saveTikTokAccount(
          account
        );

        console.log(
          '[TikTok OAuth] Account saved to Supabase'
        );

      } catch (dbError) {

        console.error(
          '[TikTok OAuth] Supabase save failed:',
          dbError.data ||
          dbError.message
        );

        return res.redirect(
          frontendRedirect(
            '/connect-tiktok.html',
            {
              tiktok:
                'error',

              error:
                'database_error'
            }
          )
        );
      }

      // ------------------------------------------------------
      // Final redirect
      // ------------------------------------------------------

      const returnTo =
        stateData.return_to ||
        '/connect-tiktok.html';

      const finalUrl =
        frontendRedirect(
          returnTo,
          {
            tiktok:
              'connected',

            open_id:
              token.open_id
          }
        );

      return res.redirect(
        finalUrl
      );

    } catch (error) {

      console.error(
        '[TikTok OAuth] Token exchange error:',
        error.data ||
        error.message
      );

      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {
            tiktok:
              'error',

            error:
              'token_exchange_failed'
          }
        )
      );
    }
  }
);

// ============================================================
// GET TIKTOK ACCOUNT
// ============================================================

app.get(
  '/tiktok/account',
  async (req, res) => {

    try {

      const openId =
        req.query.open_id;

      if (!openId) {

        return res.status(400)
          .json({
            ok: false,

            error:
              'open_id is required'
          });
      }

      const rows =
        await getTikTokAccountByOpenId(
          openId
        );

      const account =
        Array.isArray(rows)
          ? rows[0]
          : null;

      if (!account) {

        return res.status(404)
          .json({
            ok: false,

            connected:
              false,

            error:
              'TikTok account not found'
          });
      }

      return res.json({
        ok: true,

        account:
          publicAccountResponse(
            account
          )
      });

    } catch (error) {

      console.error(
        '[TikTok Account]',
        error
      );

      res.status(500)
        .json({
          ok: false,

          error:
            'Unable to retrieve TikTok account'
        });
    }
  }
);

// ============================================================
// CREATOR INFO
// ============================================================
//
// IMPORTANT:
// access_token is read ONLY from Supabase.
// It is NEVER returned to the browser.
// ============================================================

app.post(
  '/tiktok/creator-info',
  async (req, res) => {

    try {

      const openId =
        req.body.open_id;

      if (!openId) {

        return res.status(400)
          .json({
            ok: false,

            error:
              'open_id is required'
          });
      }

      const rows =
        await getTikTokAccountByOpenId(
          openId
        );

      const account =
        Array.isArray(rows)
          ? rows[0]
          : null;

      if (!account) {

        return res.status(404)
          .json({
            ok: false,

            error:
              'TikTok account not connected'
          });
      }

      const result =
        await getCreatorInfo(
          account.access_token
        );

      return res.json({
        ok: true,

        data:
          result.data ||
          {},

        error:
          result.error ||
          {
            code:
              'ok',

            message:
              ''
          }
      });

    } catch (error) {

      console.error(
        '[TikTok Creator Info]',
        error.data ||
        error.message
      );

      res.status(
        error.status || 500
      ).json({
        ok: false,

        error:
          error.data ||
          {
            message:
              error.message
          }
      });
    }
  }
);

// ============================================================
// PUBLISH STATUS
// ============================================================

app.post(
  '/tiktok/status',
  async (req, res) => {

    try {

      const {
        open_id,
        publish_id
      } = req.body;

      if (
        !open_id ||
        !publish_id
      ) {

        return res.status(400)
          .json({
            ok: false,

            error:
              'open_id and publish_id are required'
          });
      }

      const rows =
        await getTikTokAccountByOpenId(
          open_id
        );

      const account =
        Array.isArray(rows)
          ? rows[0]
          : null;

      if (!account) {

        return res.status(404)
          .json({
            ok: false,

            error:
              'TikTok account not connected'
          });
      }

      const result =
        await getPublishStatus(
          account.access_token,
          publish_id
        );

      return res.json(
        result
      );

    } catch (error) {

      console.error(
        '[TikTok Status]',
        error.data ||
        error.message
      );

      res.status(
        error.status || 500
      ).json({
        ok: false,

        error:
          error.data ||
          {
            message:
              error.message
          }
      });
    }
  }
);

// ============================================================
// REFRESH TOKEN
// ============================================================
//
// Internal endpoint.
// Do NOT expose this publicly without authentication.
// ============================================================

app.post(
  '/internal/tiktok/refresh',
  async (req, res) => {

    try {

      const {
        open_id
      } = req.body;

      if (!open_id) {

        return res.status(400)
          .json({
            ok: false,

            error:
              'open_id is required'
          });
      }

      const rows =
        await getTikTokAccountByOpenId(
          open_id
        );

      const account =
        Array.isArray(rows)
          ? rows[0]
          : null;

      if (!account) {

        return res.status(404)
          .json({
            ok: false,

            error:
              'TikTok account not found'
          });
      }

      const refreshed =
        await refreshAccessToken(
          account.refresh_token
        );

      const now =
        Date.now();

      const expiresAt =
        refreshed.expires_in
          ? new Date(
              now +
              Number(
                refreshed.expires_in
              ) *
              1000
            ).toISOString()
          : null;

      const refreshExpiresAt =
        refreshed.refresh_expires_in
          ? new Date(
              now +
              Number(
                refreshed.refresh_expires_in
              ) *
              1000
            ).toISOString()
          : account.refresh_expires_at;

      const updated = {

        account_id:
          account.account_id,

        open_id:
          account.open_id,

        access_token:
          refreshed.access_token,

        refresh_token:
          refreshed.refresh_token ||
          account.refresh_token,

        token_type:
          refreshed.token_type ||
          account.token_type ||
          'Bearer',

        scope:
          refreshed.scope ||
          account.scope,

        expires_at:
          expiresAt,

        refresh_expires_at:
          refreshExpiresAt,

        updated_at:
          new Date()
            .toISOString()
      };

      await saveTikTokAccount(
        updated
      );

      return res.json({
        ok: true,

        open_id:
          account.open_id,

        expires_at:
          expiresAt
      });

    } catch (error) {

      console.error(
        '[TikTok Refresh]',
        error.data ||
        error.message
      );

      res.status(
        error.status || 500
      ).json({
        ok: false,

        error:
          error.data ||
          {
            message:
              error.message
          }
      });
    }
  }
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {

    res.status(404)
      .json({
        ok: false,

        error:
          'Endpoint not found',

        path:
          req.path
      });
  }
);

// ============================================================
// GLOBAL ERROR
// ============================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      '[SERVER ERROR]',
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500)
      .json({
        ok: false,

        error:
          'Internal server error'
      });
  }
);

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
      `Environment: ${config.nodeEnv}`
    );

    console.log(
      `Port: ${config.port}`
    );

    console.log(
      `Public URL: ${config.serverPublicUrl}`
    );

    console.log(
      `TikTok redirect: ${config.tiktok.redirectUri}`
    );

    console.log(
      `TikTok scopes: ${config.tiktok.scopes.join(',')}`
    );

    console.log(
      '=================================================='
    );
  }
);
