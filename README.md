# Kantinakias

## JWT configuration

Set `JWT_SECRET` to a Base64-encoded random key that decodes to at least 32 bytes
before generating or validating tokens. For example, generate one with
`openssl rand -base64 32`. The secret is intentionally not stored in the repository.
`JWT_EXPIRATION_MS` optionally configures token lifetime in milliseconds; it defaults
to 86400000 (24 hours).