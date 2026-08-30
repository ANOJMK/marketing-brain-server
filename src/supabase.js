// ============================================================
// BRAIN AFRICA LABS
// SUPABASE CLIENT
// ============================================================

const config = require('./config');

async function supabaseRequest(
  path,
  options = {}
) {

  const url =
    `${config.supabase.url}${path}`;

  const headers = {
    apikey:
      config.supabase.serviceRoleKey,

    Authorization:
      `Bearer ${config.supabase.serviceRoleKey}`,

    'Content-Type':
      'application/json',

    ...(
      options.headers || {}
    )
  };

  const response =
    await fetch(
      url,
      {
        ...options,
        headers
      }
    );

  const text =
    await response.text();

  let data = null;

  try {
    data =
      text
        ? JSON.parse(text)
        : null;
  } catch {
    data = text;
  }

  if (!response.ok) {

    const error =
      new Error(
        `Supabase HTTP ${response.status}`
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }

  return data;
}

async function saveTikTokAccount(account) {

  const table =
    config.supabase.tiktokTable;

  return supabaseRequest(
    `/rest/v1/${encodeURIComponent(table)}`,
    {
      method: 'POST',

      headers: {
        Prefer:
          'resolution=merge-duplicates,return=representation'
      },

      body:
        JSON.stringify(account)
    }
  );
}

async function getTikTokAccountByOpenId(
  openId
) {

  const table =
    config.supabase.tiktokTable;

  const encoded =
    encodeURIComponent(openId);

  return supabaseRequest(
    `/rest/v1/${encodeURIComponent(table)}` +
    `?open_id=eq.${encoded}` +
    `&limit=1`,
    {
      method: 'GET'
    }
  );
}

module.exports = {
  supabaseRequest,
  saveTikTokAccount,
  getTikTokAccountByOpenId
};
