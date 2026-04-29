use serde_json::{Value, json};

fn schema(name: &str) -> Value {
    let raw = match name {
        "api-info-response" => {
            include_str!("../contracts/portal-hub/v2/api-info-response.schema.json")
        }
        "session-delete-response" => {
            include_str!("../contracts/portal-hub/v2/session-delete-response.schema.json")
        }
        "sessions-response" => {
            include_str!("../contracts/portal-hub/v2/sessions-response.schema.json")
        }
        "sync-event" => include_str!("../contracts/portal-hub/v2/sync-event.schema.json"),
        "sync-v2-put-request" => {
            include_str!("../contracts/portal-hub/v2/sync-v2-put-request.schema.json")
        }
        "sync-v2-response" => {
            include_str!("../contracts/portal-hub/v2/sync-v2-response.schema.json")
        }
        "terminal-control-message" => {
            include_str!("../contracts/portal-hub/v2/terminal-control-message.schema.json")
        }
        "terminal-start-request" => {
            include_str!("../contracts/portal-hub/v2/terminal-start-request.schema.json")
        }
        "vault-enrollment-approve-request" => {
            include_str!("../contracts/portal-hub/v2/vault-enrollment-approve-request.schema.json")
        }
        "vault-enrollment-create-request" => {
            include_str!("../contracts/portal-hub/v2/vault-enrollment-create-request.schema.json")
        }
        "vault-enrollment-list-response" => {
            include_str!("../contracts/portal-hub/v2/vault-enrollment-list-response.schema.json")
        }
        "vault-enrollment-response" => {
            include_str!("../contracts/portal-hub/v2/vault-enrollment-response.schema.json")
        }
        _ => panic!("unknown schema {name}"),
    };
    serde_json::from_str(raw)
        .unwrap_or_else(|error| panic!("{name} schema is invalid JSON: {error}"))
}

fn assert_valid(name: &str, instance: Value) {
    let schema = schema(name);
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|error| panic!("{name} schema did not compile: {error}"));
    if let Err(error) = validator.validate(&instance) {
        panic!("{name} instance failed validation: {error}\n{instance:#}");
    }
}

fn assert_invalid(name: &str, instance: Value) {
    let schema = schema(name);
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|error| panic!("{name} schema did not compile: {error}"));
    assert!(
        validator.validate(&instance).is_err(),
        "{name} instance unexpectedly validated:\n{instance:#}"
    );
}

#[test]
fn api_info_response_contract_matches_hub_capabilities() {
    assert_valid(
        "api-info-response",
        json!({
            "api_version": 2,
            "version": "0.5.0-beta.14",
            "public_url": "https://portal-hub.example.ts.net",
            "capabilities": {
                "sync_v2": true,
                "sync_events": true,
                "web_proxy": true,
                "key_vault": true,
                "vault_enrollment": true
            },
            "ssh_port": 2222,
            "ssh_username": "portal-hub"
        }),
    );
    assert_invalid(
        "api-info-response",
        json!({
            "api_version": 1,
            "version": "0.5.0-beta.14",
            "public_url": "https://portal-hub.example.ts.net",
            "capabilities": {},
            "ssh_port": 2222,
            "ssh_username": "portal-hub"
        }),
    );
}

#[test]
fn session_contracts_cover_list_and_delete_shapes() {
    let session_id = "00000000-0000-0000-0000-000000000001";
    assert_valid(
        "sessions-response",
        json!({
            "api_version": 2,
            "generated_at": "2026-04-29T12:00:00Z",
            "sessions": [{
                "schema_version": 1,
                "session_id": session_id,
                "session_name": "portal-00000000-0000-0000-0000-000000000001",
                "target_host": "example.internal",
                "target_port": 22,
                "target_user": "john",
                "created_at": "2026-04-29T11:00:00Z",
                "updated_at": "2026-04-29T11:30:00Z",
                "ended_at": null,
                "active": true,
                "last_output_at": "2026-04-29T11:29:59Z",
                "preview_base64": "cHJldmlldw==",
                "preview_truncated": false
            }]
        }),
    );
    assert_valid(
        "session-delete-response",
        json!({
            "api_version": 2,
            "session_id": session_id,
            "deleted": true,
            "process_signaled": true
        }),
    );
}

#[test]
fn sync_v2_contracts_cover_get_put_and_events() {
    assert_valid(
        "sync-v2-response",
        json!({
            "api_version": 2,
            "generated_at": "2026-04-29T12:00:00Z",
            "services": {
                "hosts": {
                    "revision": "rev-hosts",
                    "payload": { "hosts": [], "groups": [] },
                    "tombstones": []
                },
                "settings": {
                    "revision": "rev-settings",
                    "payload": {},
                    "tombstones": []
                },
                "snippets": {
                    "revision": "rev-snippets",
                    "payload": { "snippets": [] },
                    "tombstones": []
                },
                "vault": {
                    "revision": "rev-vault",
                    "payload": { "keys": [], "secrets": [] },
                    "tombstones": []
                }
            }
        }),
    );
    assert_valid(
        "sync-v2-put-request",
        json!({
            "services": {
                "hosts": {
                    "expected_revision": "rev-hosts",
                    "payload": { "hosts": [], "groups": [] },
                    "tombstones": []
                }
            }
        }),
    );
    assert_valid(
        "sync-event",
        json!({
            "api_version": 2,
            "generated_at": "2026-04-29T12:00:01Z",
            "services": {
                "hosts": "rev-hosts",
                "vault": "rev-vault"
            }
        }),
    );
    assert_invalid(
        "sync-v2-put-request",
        json!({
            "services": {
                "unknown": {
                    "expected_revision": "rev",
                    "payload": {}
                }
            }
        }),
    );
}

#[test]
fn terminal_websocket_contracts_cover_client_and_server_messages() {
    let session_id = "00000000-0000-0000-0000-000000000001";
    assert_valid(
        "terminal-start-request",
        json!({
            "session_id": session_id,
            "target_host": "example.internal",
            "target_port": 22,
            "target_user": "john",
            "cols": 120,
            "rows": 30,
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n"
        }),
    );
    assert_valid(
        "terminal-control-message",
        json!({ "type": "started", "session_id": session_id }),
    );
    assert_valid("terminal-control-message", json!({ "type": "closed" }));
    assert_valid(
        "terminal-control-message",
        json!({ "type": "error", "message": "target SSH connection failed" }),
    );
    assert_valid(
        "terminal-control-message",
        json!({ "type": "resize", "cols": 100, "rows": 40 }),
    );
}

#[test]
fn vault_enrollment_contracts_cover_android_pairing_flow() {
    let enrollment = json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "device_name": "Pixel",
        "public_key_algorithm": "RSA-OAEP-SHA256",
        "public_key_der_base64": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
        "status": "pending",
        "encrypted_secret_base64": null,
        "pairing_id": "00000000-0000-0000-0000-000000000010",
        "created_at": "2026-04-29T12:00:00Z",
        "updated_at": "2026-04-29T12:00:00Z",
        "approved_at": null,
        "revoked_at": null
    });
    assert_valid(
        "vault-enrollment-create-request",
        json!({
            "device_name": "Pixel",
            "public_key_algorithm": "RSA-OAEP-SHA256",
            "public_key_der_base64": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
            "pairing_id": "00000000-0000-0000-0000-000000000010"
        }),
    );
    assert_valid(
        "vault-enrollment-approve-request",
        json!({ "encrypted_secret_base64": "c2VjcmV0" }),
    );
    assert_valid("vault-enrollment-response", enrollment.clone());
    assert_valid("vault-enrollment-list-response", json!([enrollment]));
}
