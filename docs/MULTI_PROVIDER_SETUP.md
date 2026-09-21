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

## Google Gmail: testing versus public production

Testing mode allows only the Google accounts explicitly added as test users. For a public release, configure branding, support email, privacy policy, authorized domains, and production audience in Google Cloud Console, then submit the Gmail read scope for Google's verification/review when required. Do not switch to public until your backend is HTTPS, token storage is encrypted and tenant-isolated, and you have a real privacy policy.
