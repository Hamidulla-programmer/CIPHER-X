# Connect any user's Gmail account

CIPHER-X now uses **Google OAuth 2.0** for personal Gmail connection. Users
click **Connect Gmail securely** in the dashboard, choose their own Google
account and approve the `gmail.readonly` scope. They never provide CIPHER-X a
Gmail password or App Password.

## One-time platform setup

1. In [Google Cloud Console](https://console.cloud.google.com/), create or
   choose a project and enable the **Gmail API**.
2. Configure the OAuth consent screen. For a hackathon prototype, add your
   team Gmail addresses as test users if the app is in Testing mode.
3. Create an **OAuth client ID** of type **Web application**.
4. Add this Authorized redirect URI for local development:

   `http://127.0.0.1:8000/api/gmail/oauth/callback`

For deployment, add the exact backend URL instead, for example:

   `https://your-fastapi-service.example/api/gmail/oauth/callback`

5. Add these values to the backend host's private `.env` file (never GitHub or
   a frontend host):

   ```text
   CIPHERX_GOOGLE_CLIENT_ID=...
   CIPHERX_GOOGLE_CLIENT_SECRET=...
   CIPHERX_GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/gmail/oauth/callback
   CIPHERX_SESSION_SECRET=replace-with-a-long-random-value
   CIPHERX_FRONTEND_URL=https://your-netlify-site.netlify.app
   ```

6. Install the updated requirements and start the backend:

   ```powershell
   python -m pip install -r requirements.txt
   python -m uvicorn app.main:app --reload
   ```

## What each connected user can do

- Connect or disconnect their own Gmail from the dashboard.
- Run bulk detection for unread Inbox messages and Gmail Spam.
- Download separate forensic reports for every analyzed message.

Tokens are kept only in temporary server-side memory for this prototype and
are cleared when the user disconnects or the server restarts. A production
deployment needs encrypted database storage, a proper user-login system and
Google OAuth verification where required.

For a Netlify dashboard deployment, set `window.CIPHERX_API_BASE` in
`static/config.js` to the public FastAPI backend URL, for example
`https://cipher-x-api.onrender.com`. This is a public URL, not a secret.
