# Acme Customer Portal (login demo)

A tiny customer portal with a username/password login. It uses only the Python
standard library, so it runs anywhere without installing dependencies.

This repository exists to demonstrate the **AI support → owner approval →
auto-fix → pull request** workflow on a real project.

## Run locally

```bash
python app.py
```

Open <http://localhost:8000> and sign in:

| Username | Password |
| -------- | -------- |
| `owner`  | `demo1234` |

## Tests

```bash
python -m unittest -v
```

The GitHub Actions workflow in `.github/workflows/tests.yml` runs the same
command on every push and pull request.

## Deployment

The app is shipped as a small container image and is normally served behind a
TLS-terminating reverse proxy under a path prefix:

```bash
docker build -t login-demo .
docker run -d --name login-demo -p 8000:8000 \
  -e BASE_PATH=/login-demo \
  -e COOKIE_SECURE=true \
  login-demo
```

Environment variables:

| Variable        | Default   | Meaning                                            |
| --------------- | --------- | -------------------------------------------------- |
| `HOST`          | `0.0.0.0` | Bind address                                        |
| `PORT`          | `8000`    | Bind port                                           |
| `BASE_PATH`     | *(empty)* | Path prefix when the proxy mounts the app elsewhere |
| `COOKIE_SECURE` | `false`   | Mark the session cookie `Secure` (HTTPS deployments)|

## Health and live self-test

* `GET /healthz` → `200 ok` while the process is up.
* `GET /selftest` → runs the real `owner` / `demo1234` login check:
  * `200 login ok` when the login works,
  * `503 login fail` while the password bug is live.

The support stack calls `/selftest` after a deploy and refuses to resolve a
ticket until it returns `login ok`.

## Layout

| File                | Purpose                                             |
| ------------------- | --------------------------------------------------- |
| `app.py`            | HTTP server, routes, HTML and the login check       |
| `auth.py`           | Salted PBKDF2 password hashing and verification      |
| `test_auth.py`      | Unit tests for hashing and the login check           |
| `Dockerfile`        | Container image used for deployment                  |

## Reporting a problem

Use the chat widget on the portal (or the inbox of the support workspace) and
describe what went wrong. The request is triaged, approved by the owner, and
then a scoped fix is prepared as a pull request.
