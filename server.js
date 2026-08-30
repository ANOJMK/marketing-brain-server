// ============================================================
// BRAIN AFRICA LABS
// MARKETING BRAIN SERVER
//
// TikTok OAuth 2.0
// TikTok Creator Info
// TikTok Publish Status
// Supabase persistence
//
// VERSION: 1.1.0
// ============================================================

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const config = require('./src/config');

const {
  randomToken,
  signPayload,
  verifyPayload
} = require('./src/crypto');

const {
  buildAuthorizeUrl,
  exchangeCodeForToken,
  refreshAccessToken,
  getCreatorInfo,
  getPublishStatus
} = require('./src/tiktok');

const {
  saveTikTokAccount,
  getTikTokAccountByOpenId
} = require('./src/supabase');


// ============================================================
// APP
// ============================================================

const app = express();


// Trust reverse proxy
app.set('trust proxy', 1);


// Security
app.disable('x-powered-by');


// Body parsers
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


// ============================================================
// CORS
// ============================================================

app.use(
  cors({
    origin: config.frontendUrl,
    credentials: true
  })
);


// ============================================================
// COOKIES
// ============================================================

app.use(cookieParser());


// ============================================================
// HELPERS
// ============================================================

function safeReturnTo(value) {

  const fallback = '/connect-tiktok.html';

  if (!value) {
    return fallback;
  }

  try {

    const url = new URL(
      value,
      config.frontendUrl
    );

    const frontend = new URL(
      config.frontendUrl
    );

    const allowedHost =
      frontend.hostname;

    const allowedProtocol =
      frontend.protocol;

    // --------------------------------------------------------
    // Security:
    // return_to must stay on Brain Africa Labs frontend.
    // --------------------------------------------------------

    if (
      url.hostname !== allowedHost ||
      url.protocol !== allowedProtocol
    ) {
      return fallback;
    }

    return (
      url.pathname +
      url.search
    );

  } catch {

    // Relative path only
    if (
      String(value).startsWith('/')
    ) {
      return String(value);
    }

    return fallback;
  }
}


// ============================================================
// FRONTEND REDIRECT
// ============================================================

function frontendRedirect(
  path,
  params = {}
) {

  const base =
    new URL(config.frontendUrl);

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


// ============================================================
// OAUTH COOKIE OPTIONS
// ============================================================

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


// ============================================================
// PUBLIC ACCOUNT RESPONSE
//
// NEVER return access_token or refresh_token.
// ============================================================

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
      account.display_name ||
      null,

    avatar_url:
      account.avatar_url ||
      null,

    scope:
      account.scope ||
      null,

    expires_at:
      account.expires_at ||
      null,

    refresh_expires_at:
      account.refresh_expires_at ||
      null,

    token_type:
      account.token_type ||
      'Bearer',

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
        '1.1.0',

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

      version:
        '1.1.0',

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
//
// https://brainafricalabs.com/connect-tiktok.html
//
// redirects to:
//
// https://oauth.brainafricalabs.com/tiktok/authorize
//
// Then this endpoint redirects to TikTok.
//
// ============================================================

app.get(
  '/tiktok/authorize',
  (req, res) => {

    try {

      // ------------------------------------------------------
      // Return destination
      // ------------------------------------------------------

      const returnTo =
        safeReturnTo(
          req.query.return_to
        );


      // ------------------------------------------------------
      // Optional campaign
      // ------------------------------------------------------

      const campaignId =
        req.query.campaign_id ||
        null;


      // ------------------------------------------------------
      // Generate OAuth nonce
      // ------------------------------------------------------

      const nonce =
        randomToken(32);


      // ------------------------------------------------------
      // Signed OAuth state
      // ------------------------------------------------------

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


      // ------------------------------------------------------
      // Save nonce in HTTP-only cookie
      // ------------------------------------------------------

      res.cookie(
        'tiktok_oauth_nonce',
        nonce,
        cookieOptions()
      );


      // ------------------------------------------------------
      // Build TikTok OAuth URL
      // ------------------------------------------------------

      const authorizeUrl =
        buildAuthorizeUrl({
          state
        });


      console.log(
        '[TikTok OAuth] Authorization started'
      );

      console.log(
        '[TikTok OAuth] Return to:',
        returnTo
      );


      // ------------------------------------------------------
      // Redirect to TikTok
      // ------------------------------------------------------

      return res.redirect(
        authorizeUrl
      );

    } catch (error) {

      console.error(
        '[TikTok OAuth] authorize error:',
        error
      );

      return res.status(500).send(
        `
        <!doctype html>
        <html lang="en">

        <head>
          <meta charset="utf-8">
          <meta name="viewport"
                content="width=device-width,initial-scale=1">
          <title>TikTok Authorization Error</title>
        </head>

        <body>

          <h1>TikTok Authorization Error</h1>

          <p>
            Unable to start TikTok authorization.
          </p>

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
//
// TikTok redirects here after authorization:
//
// https://oauth.brainafricalabs.com/tiktok/callback
//
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


    // ========================================================
    // TIKTOK RETURNED AN ERROR
    // ========================================================

    if (error) {

      console.error(
        '[TikTok OAuth] TikTok returned error:',
        error,
        error_description
      );


      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {

            connected:
              'false',

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


    // ========================================================
    // CODE / STATE REQUIRED
    // ========================================================

    if (!code || !state) {

      console.error(
        '[TikTok OAuth] Missing code or state'
      );


      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {

            connected:
              'false',

            tiktok:
              'error',

            error:
              'missing_code_or_state'
          }
        )
      );
    }


    // ========================================================
    // VERIFY SIGNED STATE
    // ========================================================

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


      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {

            connected:
              'false',

            tiktok:
              'error',

            error:
              'invalid_state'
          }
        )
      );
    }


    // ========================================================
    // VERIFY STATE EXPIRATION
    // ========================================================

    const age =
      Date.now() -
      Number(
        stateData.created_at ||
        0
      );


    if (
      !Number.isFinite(age) ||
      age < 0 ||
      age >
        10 * 60 * 1000
    ) {

      console.error(
        '[TikTok OAuth] State expired'
      );


      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {

            connected:
              'false',

            tiktok:
              'error',

            error:
              'state_expired'
          }
        )
      );
    }


    // ========================================================
    // VERIFY NONCE COOKIE
    // ========================================================

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


      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {

            connected:
              'false',

            tiktok:
              'error',

            error:
              'nonce_mismatch'
          }
        )
      );
    }


    // ========================================================
    // DELETE OAUTH COOKIE
    // ========================================================

    res.clearCookie(
      'tiktok_oauth_nonce',
      {
        httpOnly: true,

        secure:
          config.nodeEnv ===
          'production',

        sameSite:
          'lax',

        path:
          '/'
      }
    );


    // ========================================================
    // EXCHANGE CODE FOR TOKEN
    // ========================================================

    try {

      const token =
        await exchangeCodeForToken(
          code
        );


      console.log(
        '[TikTok OAuth] Token exchange successful'
      );


      // ------------------------------------------------------
      // Validate TikTok response
      // ------------------------------------------------------

      if (
        !token ||
        !token.access_token ||
        !token.open_id
      ) {

        throw new Error(
          'TikTok token response missing access_token or open_id.'
        );
      }


      // ======================================================
      // EXPIRATION
      // ======================================================

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


      // ======================================================
      // ACCOUNT OBJECT
      // ======================================================

      const account = {

        account_id:
          config.defaultAccountId,

        open_id:
          token.open_id,

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


      // ======================================================
      // SAVE ACCOUNT IN SUPABASE
      // ======================================================

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
          dbError?.data ||
          dbError?.message ||
          dbError
        );


        return res.redirect(
          frontendRedirect(
            '/connect-tiktok.html',
            {

              connected:
                'false',

              tiktok:
                'error',

              error:
                'database_error'
            }
          )
        );
      }


      // ======================================================
      // OPTIONAL CREATOR INFORMATION
      // ======================================================
      //
      // We try to retrieve creator information.
      //
      // Failure here must NOT invalidate the successful OAuth
      // connection because the token has already been saved.
      //
      // ======================================================

      let creatorUsername = null;
      let creatorNickname = null;


      try {

        const creatorResult =
          await getCreatorInfo(
            token.access_token
          );


        const creator =
          creatorResult?.data ||
          {};


        creatorUsername =
          creator.creator_username ||
          creator.username ||
          null;


        creatorNickname =
          creator.creator_nickname ||
          creator.nickname ||
          null;


        console.log(
          '[TikTok OAuth] Creator info retrieved'
        );


      } catch (creatorError) {

        console.warn(
          '[TikTok OAuth] Creator info unavailable:',
          creatorError?.data ||
          creatorError?.message ||
          creatorError
        );

      }


      // ======================================================
      // FINAL FRONTEND REDIRECT
      // ======================================================
      //
      // IMPORTANT:
      //
      // connect-tiktok.html expects:
      //
      // connected=true
      //
      // We therefore explicitly send connected=true.
      //
      // ======================================================

      const returnTo =
        stateData.return_to ||
        '/connect-tiktok.html';


      const finalUrl =
        frontendRedirect(
          returnTo,
          {

            // ----------------------------------------------
            // FRONTEND SUCCESS FLAG
            // ----------------------------------------------

            connected:
              'true',


            // ----------------------------------------------
            // TikTok status
            // ----------------------------------------------

            tiktok:
              'connected',


            // ----------------------------------------------
            // TikTok Open ID
            // ----------------------------------------------

            open_id:
              token.open_id,


            // ----------------------------------------------
            // Optional display information
            // ----------------------------------------------

            account_name:
              creatorNickname ||
              'TikTok account',


            username:
              creatorUsername ||
              ''
          }
        );


      console.log(
        '[TikTok OAuth] Authorization completed'
      );


      console.log(
        '[TikTok OAuth] Redirecting frontend:',
        returnTo
      );


      return res.redirect(
        finalUrl
      );


    } catch (error) {

      console.error(
        '[TikTok OAuth] Token exchange error:',
        error?.data ||
        error?.message ||
        error
      );


      return res.redirect(
        frontendRedirect(
          '/connect-tiktok.html',
          {

            connected:
              'false',

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
//
// GET:
//
// /tiktok/account?open_id=XXXX
//
// Tokens are NEVER returned.
//
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


      return res.status(500)
        .json({

          ok: false,

          error:
            'Unable to retrieve TikTok account'
        });
    }
  }
);


// ============================================================
// TIKTOK CREATOR INFO
// ============================================================
//
// POST /tiktok/creator-info
//
// Body:
//
// {
//   "open_id": "..."
// }
//
// access_token is read from Supabase only.
//
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


      // ------------------------------------------------------
      // Find account
      // ------------------------------------------------------

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


      // ------------------------------------------------------
      // Call TikTok Creator Info
      // ------------------------------------------------------

      const result =
        await getCreatorInfo(
          account.access_token
        );


      return res.json({

        ok: true,

        data:
          result?.data ||
          {},

        error:
          result?.error ||
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
        error?.data ||
        error?.message ||
        error
      );


      return res.status(
        error?.status ||
        500
      ).json({

        ok: false,

        error:
          error?.data ||
          {
            message:
              error?.message ||
              'Creator info request failed.'
          }
      });
    }
  }
);


// ============================================================
// TIKTOK PUBLISH STATUS
// ============================================================
//
// POST /tiktok/status
//
// Body:
//
// {
//   "open_id": "...",
//   "publish_id": "..."
// }
//
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


      // ------------------------------------------------------
      // Find TikTok account
      // ------------------------------------------------------

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


      // ------------------------------------------------------
      // Query TikTok
      // ------------------------------------------------------

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
        error?.data ||
        error?.message ||
        error
      );


      return res.status(
        error?.status ||
        500
      ).json({

        ok: false,

        error:
          error?.data ||
          {
            message:
              error?.message ||
              'Unable to retrieve TikTok publish status.'
          }
      });
    }
  }
);


// ============================================================
// INTERNAL TOKEN REFRESH
// ============================================================
//
// POST /internal/tiktok/refresh
//
// Body:
//
// {
//   "open_id": "..."
// }
//
// IMPORTANT:
// This endpoint should ideally be protected by an internal
// secret or called only from a private backend/network.
//
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


      // ------------------------------------------------------
      // Find account
      // ------------------------------------------------------

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


      if (!account.refresh_token) {

        return res.status(400)
          .json({

            ok: false,

            error:
              'TikTok refresh token unavailable'
          });
      }


      // ------------------------------------------------------
      // Refresh
      // ------------------------------------------------------

      const refreshed =
        await refreshAccessToken(
          account.refresh_token
        );


      // ------------------------------------------------------
      // Calculate new expiration
      // ------------------------------------------------------

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


      // ------------------------------------------------------
      // Update account
      // ------------------------------------------------------

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


      console.log(
        '[TikTok Refresh] Token refreshed successfully'
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
        error?.data ||
        error?.message ||
        error
      );


      return res.status(
        error?.status ||
        500
      ).json({

        ok: false,

        error:
          error?.data ||
          {
            message:
              error?.message ||
              'TikTok token refresh failed.'
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

    return res.status(404)
      .json({

        ok: false,

        error:
          'Endpoint not found',

        path:
          req.path,

        method:
          req.method
      });
  }
);


// ============================================================
// GLOBAL ERROR HANDLER
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


    if (
      res.headersSent
    ) {
      return next(error);
    }


    return res.status(500)
      .json({

        ok: false,

        error:
          'Internal server error'
      });
  }
);


// ============================================================
// START SERVER
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
      'Version: 1.1.0'
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
      '=================================================='
    );
  }
);
