# ECE 435L · Incident Management API (teaching sample)

**A small backend demonstration** of incident reporting, role-based permissions, validation, and audit logging for the *Security Incident Detection and Response Management System* assignment.

> **Scope:** Illustrative subset only. This example covers incident creation/list/detail/assignment/status/notes, demo login, and an audit-log view. It **does not implement all nine services**, cross-service API calls, or the complete course deliverables. Do not submit or copy this code as your own work.

## Start in three steps (Python 3.10+; no external packages)

```bash
# From repository root (Linux, macOS, or Git Bash)
export PYTHONPATH=src
export DEMO_PASSWORD='choose-a-local-password-123'
python -m incident_demo.seed
python -m incident_demo
```

In Windows PowerShell, use `$env:PYTHONPATH='src'` and `$env:DEMO_PASSWORD='choose-a-local-password-123'` instead of `export`. By default the API runs at `http://127.0.0.1:8765`. Stop with Ctrl+C.

`DEMO_PASSWORD` is for **local testing only**; it is *not stored in the repository*. Fictional users: `demo_admin`, `demo_analyst`, `demo_employee`, and `demo_auditor`. Each uses the password you supplied at initial seeding. Delete `data/demo.sqlite3` before changing the seeded password. Passwords in the database are salted and hashed.

## First request

```bash
curl -X POST http://127.0.0.1:8765/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo_employee","password":"choose-a-local-password-123"}'
```

Copy the **actual** `access_token` returned by your running server and use it in `Authorization: Bearer <token>` for protected requests. See [API reference](docs/API.md) for a request example, the full route list, permissions, and expected status codes.

## Tests and Postman

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Import [`postman/ECE435L_Incident_Demo.postman_collection.json`](postman/ECE435L_Incident_Demo.postman_collection.json) in Postman, select the requests in order, and set the collection variable `base_url` if needed. Login requests capture tokens into role-specific collection variables. The collection describes real requests to execute; it does **not** contain fabricated screenshots or outputs.

## Repository map

| Location | Purpose |
|---|---|
| `src/incident_demo/` | HTTP routes, password security, SQLite persistence, local demo seeding |
| `tests/` | HTTP integration tests for login, RBAC, lifecycle, and validation |
| `docs/` | Architecture, owner map, API reference, and evidence checklist |
| `postman/` | Importable Postman collection |
| `.github/workflows/` | Automated test workflow |

## Contribution and evidence boundaries

Fictional group: **Amal Haddad**, **Karim Daher**, **Lina Khoury**. Ownership is labeled beside routes in the source and in [contributions](docs/CONTRIBUTIONS.md). Local Git commits use fictional demo identities only; real student teams must commit from their own GitHub accounts and generate **genuine screenshots and responses from their own implementation**. See [evidence checklist](docs/EVIDENCE_CHECKLIST.md).

## Limitations

This is a classroom-quality teaching example, **not production security software**. Tokens exist only in process memory and vanish on restart; there is no rate-limiting, TLS, external identity provider, asset service, or complete nine-service composition. The review activity assesses clear repository communication and visible engineering practices, not completeness of the system.

## References / AI use

- Assignment: *ECE 435L Assignment — Security Incident Detection and Response Management System Backend, Sprint I*.
- Python standard-library documentation for `http.server`, `sqlite3`, `hashlib`, `secrets`, and `unittest`.
- This fictional educational sample was created with AI assistance for an MSFEA CREATES repository-review activity. It is not a student submission.
