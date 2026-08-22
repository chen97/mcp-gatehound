# Test fixtures

## `mock_server.py`

Stands in for **both** the Beeper Desktop API and the Anthropic Messages API on a single
port, so the whole chain can be exercised without a Beeper account, a Claude subscription or
a network connection.

```sh
python3 tests_fixtures/mock_server.py 23399
```

Its chat fixtures each pin down one behaviour that is easy to regress:

| Chat | What it proves |
|---|---|
| Alice (WhatsApp) | An ordinary English thread produces an English draft |
| Dana 小美 (Telegram) | A Chinese thread produces a Chinese draft — the model mirrors the language rather than translating |
| Bob (Telegram) | The owner already replied, so the chat is not surfaced at all |
| Glassnode (Telegram) | A network bot is filtered out |
| Carol (WhatsApp) | A sticker-only message yields `[NO_REPLY]` and no draft |

`GET /__mock/sent` reports what was actually sent and marked read, which is how the
idempotency tests prove a replayed send reached the upstream exactly once.

## `gatehound.mock.toml`

The gateway configuration that points at the mock rig. See the repository README for the two
commands that bring the whole thing up.

## `test_rsa.pem` and `test_jwks.json`

**A throwaway RSA key pair, generated solely so the Cloudflare Access JWT tests can sign
tokens locally.** It guards nothing, it is not used at runtime by any code path, and it
protects no account, service or environment — it exists so `auth.rs` can assert that a valid
token is accepted and that wrong-audience, wrong-issuer, expired and malformed tokens are all
rejected, without reaching the network.

Secret scanners flag it because it is a private key in a public repository. That report is
correct about what the file is and harmless in what it means. Do not reuse this key for
anything, and do not treat its presence as a precedent for committing real ones.
