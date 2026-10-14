# API reference · fictional owner map

The full name next to each route identifies the fictional student responsible for that API. Paths retain normal REST naming. All payloads are JSON. Protected routes require `Authorization: Bearer <token>` returned by login.

| Method | Endpoint | Allowed role / scope | Responsible student | Typical success |
|---|---|---|---|---|
| GET | `/health` | Public | Amal Haddad | 200 |
| POST | `/auth/login` | Public, valid seeded account | Karim Daher | 200 |
| POST | `/incidents` | Administrator or employee | Lina Khoury | 201 |
| GET | `/incidents` | Administrator or auditor | Lina Khoury | 200 |
| GET | `/incidents/{id}` | Administrator/auditor; reporter or assigned analyst | Lina Khoury | 200 |
| PUT | `/incidents/{id}/assign` | Administrator | Amal Haddad | 200 |
| PUT | `/incidents/{id}/status` | Administrator or assigned analyst | Lina Khoury | 200 |
| POST | `/incidents/{id}/notes` | Administrator or assigned analyst | Lina Khoury | 201 |
| GET | `/audit-logs` | Administrator or auditor | Karim Daher | 200 |

## Example: submit incident (Lina Khoury)

`POST /incidents`

```http
Authorization: Bearer <your token from /auth/login>
Content-Type: application/json
```

```json
{
  "title": "Suspicious sign-in",
  "description": "Employee reported an unexpected authentication prompt",
  "category": "Account compromise",
  "severity": "High",
  "affected_asset": "LAPTOP-01"
}
```

A successful request returns **201 Created**, a generated incident ID, and status `Open`. A missing field or invalid severity returns **400**. An unauthorized role returns **403**, and missing/invalid credentials return **401**. A nonexistent incident returns **404**. Skipping a lifecycle state returns **409 Conflict**.

## Lifecycle

`Open → Under Investigation → Mitigated → Resolved → Closed`. A role check and a transition check run before update. An unassigned analyst cannot update or add notes to another analyst's incident.

## Error shape

```json
{"status": "error", "message": "Human-readable reason"}
```

The snippets on this page are documentation **requests/response formats**, not screenshots or proof of actual execution. For assessment, produce your own real Postman executions and screenshots with captions.
