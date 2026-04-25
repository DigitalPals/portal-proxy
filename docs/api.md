# Portal Proxy API

Portal Proxy is executed over SSH forced commands. New clients should request
versioned JSON responses and reject unknown API versions.

## Version

```sh
portal-proxy version --json
```

Response:

```json
{
  "version": "0.5.0-beta.3",
  "api_version": 1,
  "metadata_schema_version": 1,
  "min_portal_api_version": 1
}
```

## List Sessions

```sh
portal-proxy list --active --include-preview --preview-bytes 524288 --format v1
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
- Clients may continue to parse the legacy array output for older proxies.
- `preview_base64` is omitted when `--include-preview` is not set or logging is
  disabled.

## Attach

```sh
portal-proxy attach \
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
portal-proxy doctor --json
```

Reports dependency and state directory checks. A non-zero exit code means one or
more checks failed.

## Prune

```sh
portal-proxy prune --dry-run
portal-proxy prune --ended-older-than-days 14 --max-log-bytes 67108864
```

Prune prints a JSON report with deleted sessions, truncated logs, and reclaimed
bytes.
