# Test fixtures

## `mock_upstream.py`

A small REST service the gateway can front, so `proxy` actions can be exercised without any
real API. It holds three notes behind a bearer token and records what was written to
`GET /__mock/writes`, which is how the idempotency test proves a replayed call reached the
upstream exactly once.

```sh
python3 tests_fixtures/mock_upstream.py 23399
```

One of the note identifiers is `!odd:host.local`. Those characters are legal inside a URL
path segment, and the gateway must pass them through without mangling or double-encoding
them — a class of bug that only shows up against a real identifier scheme.

## `gatehound.mock.toml`

The gateway configuration pointing at that service: one `http` upstream with three declared
operations, four tools bound to them, and a seeded identity.

## `test_rsa.pem` and `test_jwks.json`

**A throwaway RSA key pair, generated solely so the Cloudflare Access JWT tests can sign
tokens locally.** It guards nothing, it is not used at runtime by any code path, and it
protects no account, service or environment — it exists so `auth.rs` can assert that a valid
token is accepted and that wrong-audience, wrong-issuer, expired and malformed tokens are all
rejected, without reaching the network.

Secret scanners flag it because it is a private key in a public repository. That report is
correct about what the file is and harmless in what it means. Do not reuse this key for
anything, and do not treat its presence as a precedent for committing real ones.
