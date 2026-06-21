# web-keys

Railway-ready Node.js service.

Routes:

- `GET /login` returns `1154070`
- `POST /decypher` accepts `multipart/form-data` fields `key` and `secret`, decrypts `secret` with the private RSA key from `key`, and returns the decrypted text as `text/plain`

Railway will provide HTTPS on its public domain. The app listens on `process.env.PORT`.
