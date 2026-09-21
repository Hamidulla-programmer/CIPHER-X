# CIPHER-X public test deployment

Public dashboard: `https://cipher-x-main.netlify.app`

Backend API: `https://cipher-x-1.onrender.com`

The Netlify frontend is configured in `static/config.js` to call the backend URL above.

## Render environment variables

Set these in Render service **cipher-x-1** → Environment:

```text
CIPHERX_FRONTEND_URL=https://cipher-x-main.netlify.app
CIPHERX_SESSION_SECRET=<long random secret>
CIPHERX_GOOGLE_CLIENT_ID=<Google OAuth client ID>
CIPHERX_GOOGLE_CLIENT_SECRET=<Google OAuth client secret>
CIPHERX_GOOGLE_REDIRECT_URI=https://cipher-x-1.onrender.com/api/gmail/oauth/callback
CIPHERX_MICROSOFT_CLIENT_ID=<Microsoft Entra client ID>
CIPHERX_MICROSOFT_CLIENT_SECRET=<Microsoft Entra client secret>
CIPHERX_MICROSOFT_REDIRECT_URI=https://cipher-x-1.onrender.com/api/mail/oauth/outlook/callback
```

Do not set `PORT`. Render provides it automatically. Do not add any of the above secrets to Netlify or GitHub.

## Provider console redirect URIs

Add the exact matching public callback to each registered OAuth application:

| Provider | Required callback |
|---|---|
| Google Gmail | `https://cipher-x-1.onrender.com/api/gmail/oauth/callback` |
| Outlook / Microsoft 365 | `https://cipher-x-1.onrender.com/api/mail/oauth/outlook/callback` |

## Deployment order

1. Push the code to GitHub.
2. In Render, deploy the latest commit with base directory empty, build command `pip install -r requirements.txt`, and start command `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
3. Add/update the Render environment variables, then redeploy.
4. In Netlify, deploy from `main` with base directory empty, no build command, and publish directory `static`.
5. Open the Netlify URL and test the `Upload .eml file` flow first. It confirms that frontend-to-backend routing works before provider OAuth is configured.
