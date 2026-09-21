# Multi-provider mailbox setup

All connectors are read-only and each provider needs its own OAuth application.
Keep credentials only in `.env` or protected deployment environment variables.

## Microsoft Outlook / Microsoft 365

1. Open Microsoft Entra admin center → **App registrations** → **New registration**.
2. Select **Accounts in any organizational directory and personal Microsoft accounts**.
3. Add platform **Web** and redirect URI:
   `http://127.0.0.1:8000/api/mail/oauth/outlook/callback`
4. Copy **Application (client) ID**.
5. Open **Certificates & secrets**, create a client secret, and copy its **Value** immediately.
6. Under **API permissions**, add delegated Microsoft Graph permissions: `User.Read` and `Mail.Read`.
7. Add the values to `.env` using the `CIPHERX_MICROSOFT_*` names in `.env.example`.

For deployment replace the redirect URI in both Microsoft Entra and the backend environment variable with the exact public backend URL, for example `https://api.example.org/api/mail/oauth/outlook/callback`.

## Yahoo Mail

1. Sign in at Yahoo Developer Network and create a **server-side** application/project.
2. Set the application domain and callback URI to:
   `http://127.0.0.1:8000/api/mail/oauth/yahoo/callback`
3. Request `openid` and `mail-r` read scope.
4. Copy the Consumer Key as `CIPHERX_YAHOO_CLIENT_ID` and Consumer Secret as `CIPHERX_YAHOO_CLIENT_SECRET`.
5. Set `CIPHERX_YAHOO_REDIRECT_URI` to the identical callback URI.

The Yahoo connector uses OAuth-authenticated IMAP in read-only mode to examine unread Inbox and Spam/Bulk Mail messages. Provider permission availability can vary by account and Yahoo application approval.

## Google Gmail: testing versus public production

Testing mode allows only the Google accounts explicitly added as test users. For a public release, configure branding, support email, privacy policy, authorized domains, and production audience in Google Cloud Console, then submit the Gmail read scope for Google's verification/review when required. Do not switch to public until your backend is HTTPS, token storage is encrypted and tenant-isolated, and you have a real privacy policy.
