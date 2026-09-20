# Nuvemshop Tracking

Cloudflare Worker for the Nuvemshop integration.

Routes:

- `GET /health`: public deployment check.
- `GET /nuvemshop/install`: starts OAuth authorization with a temporary state cookie.
- `GET /nuvemshop/oauth/callback`: exchanges the code and stores an encrypted token.
- `POST /nuvemshop/webhook`: verifies the request signature and records order events.

Provision the D1 database named in `wrangler.jsonc`, then apply `schema.sql` to
the remote database. Configure `CLIENT_SECRET` and `TOKEN_ENCRYPTION_KEY` as
Cloudflare Worker secrets. The encryption key must be 32 random bytes encoded
as base64. Never commit either secret or a store access token to Git.

The webhook currently records `order/created` and `order/paid` only. It does not
yet fetch order details, reconcile checkout IDs, or send conversions to Stape.
Register those webhooks after the downstream processing is ready.

The root-level `wrangler.jsonc` is used by Cloudflare Builds with the deploy
command `npx wrangler deploy`.

