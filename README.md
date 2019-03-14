# Vault Client

This crate is a thin wrapper around [Vault](https://www.vaultproject.io/) HTTP API.

## Tests

You need to start a Vault server in development mode to run tests.

```bash
vault server -dev -dev-root-token-id=12345
```

Then, you can run tests using

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=12345 cargo test
```
