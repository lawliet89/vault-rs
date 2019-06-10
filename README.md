# Vault Client

This crate is a thin wrapper around [Vault](https://www.vaultproject.io/) HTTP API.

## Tests

You need to start a Vault server in development mode and some other mock servers to run tests.

```bash
docker-compose -f tests/docker-compose.yml up --build
```

Then, you can run tests using

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=12345 cargo test
```
