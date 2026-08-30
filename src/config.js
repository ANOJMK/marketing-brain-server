// ============================================================
// BRAIN AFRICA LABS
// CONFIGURATION
// ============================================================

require('dotenv').config();

function required(name) {
  const value = process.env[name];

  if (!value || !String(value).trim()) {
    throw new Error(
      `Variable d'environnement manquante: ${name}`
    );
  }

  return String(value).trim();
}

const config = {
  nodeEnv:
    process.env.NODE_ENV || 'development',

  port:
    Number(process.env.PORT || 3000),

  serverPublicUrl:
    required('SERVER_PUBLIC_URL')
      .replace(/\/+$/, ''),

  frontendUrl:
    required('FRONTEND_URL')
      .replace(/\/+$/, ''),

  tiktok: {
    clientKey:
      required('TIKTOK_CLIENT_KEY'),

    clientSecret:
      required('TIKTOK_CLIENT_SECRET'),

    redirectUri:
      required('TIKTOK_REDIRECT_URI'),

    scopes:
      String(
        process.env.TIKTOK_SCOPES ||
        'user.info.basic,video.publish'
      )
        .split(',')
        .map(v => v.trim())
        .filter(Boolean)
  },

  security: {
    oauthStateSecret:
      required('OAUTH_STATE_SECRET')
  },

  supabase: {
    url:
      required('SUPABASE_URL')
        .replace(/\/+$/, ''),

    serviceRoleKey:
      required('SUPABASE_SERVICE_ROLE_KEY'),

    tiktokTable:
      process.env.SUPABASE_TIKTOK_TABLE ||
      'tiktok_oauth_accounts'
  },

  defaultAccountId:
    Number(
      process.env.DEFAULT_ACCOUNT_ID || 2
    )
};

module.exports = config;
