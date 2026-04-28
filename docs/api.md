# Portal Hub API

Portal Hub exposes OAuth-authenticated web APIs for Portal desktop. The legacy
SSH forced-command CLI remains available for deployments and compatibility.
Clients should request versioned JSON responses and reject unknown API versions.

## Version

```sh
portal-hub version --json
```

Response:

```json
{
  "version": "0.5.0-beta.6",
  "api_version": 1,
  "metadata_schema_version": 1,
  "min_portal_api_version": 1
}
```

## List Sessions

```sh
portal-hub list --active --include-preview --preview-bytes 524288 --format v1
```

Response:

```json
{
  "api_version": 1,
  "generated_at": "2026-04-25T00:00:00Z",
  "sessions": [
    {
      "schema_version": 1,
      "session_id": "00000000-0000-0000-0000-000000000001",
      "session_name": "portal-00000000-0000-0000-0000-000000000001",
      "target_host": "example.internal",
      "target_port": 22,
      "target_user": "john",
      "created_at": "2026-04-25T00:00:00Z",
      "updated_at": "2026-04-25T00:10:00Z",
      "ended_at": null,
      "active": true,
      "last_output_at": "2026-04-25T00:09:59Z",
      "preview_base64": "Li4u",
      "preview_truncated": false
    }
  ]
}
```

Compatibility notes:

- `api_version` is currently `1`.
- New CLI clients should call `portal-hub list --format v1`.
- `preview_base64` is omitted when `--include-preview` is not set or logging is
  disabled.

## Sync

```sh
portal-hub sync get --format v1
```

Response:

```json
{
  "api_version": 1,
  "generated_at": "2026-04-25T00:00:00Z",
  "revision": "0",
  "profile": {
    "hosts": { "hosts": [], "groups": [] },
    "settings": {},
    "snippets": { "snippets": [] }
  },
  "vault": { "keys": [] }
}
```

Replace the sync profile only when the caller has the latest revision:

```sh
portal-hub sync put --expected-revision 0 --format v1 < sync-request.json
```

The request body is a JSON object with `profile` and `vault` fields. Portal Hub
stores `profile` as readable JSON for hosts, settings, and snippets. The `vault`
field stores encrypted private-key blobs; Portal encrypts and decrypts those
keys locally, so Hub never receives the vault passphrase or decrypted private
keys.

If `--expected-revision` is stale, the command exits non-zero and leaves the
stored profile unchanged.

## Web Auth And HTTPS Sync

Run the web server:

```sh
portal-hub web --bind 0.0.0.0:8080 --public-url https://hub.example.test
```

When no user exists, `GET /admin` presents the one-time owner setup wizard. The
wizard asks for an account name and password.

Portal desktop authenticates with OAuth authorization code + PKCE:

```text
GET /oauth/authorize?response_type=code&client_id=portal-desktop&redirect_uri=http://127.0.0.1:PORT/callback&code_challenge=...&code_challenge_method=S256&state=...
POST /oauth/token
```

The browser page served by `GET /oauth/authorize` signs the user in with the
owner password before issuing the OAuth authorization code.

The token response contains a bearer `access_token` and `refresh_token`.
Authenticated clients can call:

```text
GET /api/info
GET /api/me
GET /api/sync
PUT /api/sync
GET /api/sync/v2
PUT /api/sync/v2
GET /api/sync/v2/events
GET /api/vault/enrollments
POST /api/vault/enrollments
GET /api/vault/enrollments/{id}
POST /api/vault/enrollments/{id}/approve
GET /api/sessions
GET /api/sessions/terminal
```

`GET /api/info` is public metadata for desktop onboarding. It returns the Hub
version, public URL, and capability flags so clients can derive OAuth and proxy
settings from a host plus web port.

Example:

```json
{
  "api_version": 2,
  "version": "0.5.0-beta.6",
  "public_url": "https://hub.example.test",
  "capabilities": {
    "sync_v2": true,
    "sync_events": true,
    "web_proxy": true,
    "key_vault": true,
    "vault_enrollment": true
  },
  "ssh_port": 2222,
  "ssh_username": "portal-hub"
}
```

`PUT /api/sync` accepts `expected_revision`, `profile`, and `vault`. A stale
revision returns HTTP `409 Conflict`.

`/api/sync/v2` stores independent service payloads for `hosts`, `settings`,
`snippets`, and `vault`. Each service has its own `revision`, `payload`, and
`tombstones` array. `PUT /api/sync/v2` accepts a `services` object whose values
contain `expected_revision`, `payload`, and optional `tombstones`; stale service
revisions return HTTP `409 Conflict`.

`GET /api/sync/v2/events` is a bearer-authenticated SSE stream. It emits `sync`
events with the latest service revision map so Portal can run background sync
after another device updates the Hub.

Vault enrollment lets a new device obtain the existing vault unlock key without
Hub seeing that key. Android creates an RSA public/private key pair and calls
`POST /api/vault/enrollments` with `device_name`,
`public_key_algorithm: "RSA-OAEP-SHA256"`, and `public_key_der_base64`.
Portal desktop lists pending requests with `GET /api/vault/enrollments`, reads
the vault unlock key from its OS keychain, encrypts it to the device public key,
and calls `POST /api/vault/enrollments/{id}/approve` with
`encrypted_secret_base64`. Android polls `GET /api/vault/enrollments/{id}`,
decrypts the envelope locally, and stores the unlock key in Android Keystore.
Hub stores only public keys, request status, and encrypted envelopes.

`GET /api/sessions` requires a bearer token and returns the versioned session
list used by Portal's active-session picker. `active=true`, `include_preview`,
and `preview_bytes` are supported query parameters.

`GET /api/sessions/terminal` upgrades to a bearer-authenticated WebSocket. The
first client message is a JSON terminal start request with `session_id`,
`target_host`, `target_port`, `target_user`, `cols`, `rows`, and optional
`private_key`. Hub replies with `{"type":"started"}` or `{"type":"error"}`.
Binary WebSocket messages carry terminal input and output. Resize control
messages use `{"type":"resize","cols":120,"rows":30}`.

## Attach

```sh
portal-hub attach \
  --session-id 00000000-0000-0000-0000-000000000001 \
  --target-host example.internal \
  --target-port 22 \
  --target-user john \
  --cols 120 \
  --rows 30
```

Attach uses the process standard input/output as the terminal stream. Closing
the client detaches. Exiting the remote shell ends the session.

## Doctor

```sh
portal-hub doctor --json
```

Reports dependency and state directory checks. A non-zero exit code means one or
more checks failed.

## Prune

```sh
portal-hub prune --dry-run
portal-hub prune --ended-older-than-days 14 --max-log-bytes 16777216
```

Prune prints a JSON report with deleted sessions, truncated logs, and reclaimed
bytes.
