"""Small REST interface for ECE 435L incident management.

Illustrative subset, NOT a full implementation of the nine-service assignment.
Each route's responsible fictional student is documented in docs/API.md.
"""
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from .security import Principal, SessionStore, verify_password
from .storage import connect, init_db, utc_now, write_audit

SEVERITIES = {'Low', 'Medium', 'High', 'Critical'}
STATUSES = ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')


def create_server(host: str, port: int, db_path: str) -> HTTPServer:
    init_db(db_path)
    sessions = SessionStore()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, code: int, payload: dict | list):
            raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def fail(self, code: int, message: str):
            self.reply(code, {'status': 'error', 'message': message})

        def body(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if length < 1 or length > 65536:
                    return None
                value = json.loads(self.rfile.read(length))
                return value if isinstance(value, dict) else None
            except (ValueError, json.JSONDecodeError):
                return None

        def principal(self) -> Principal | None:
            header = self.headers.get('Authorization', '')
            token = header.removeprefix('Bearer ').strip() if header.startswith('Bearer ') else ''
            return sessions.lookup(token)

        def require(self, permitted: set[str], action: str) -> Principal | None:
            actor = self.principal()
            if actor is None:
                with connect(db_path) as db:
                    write_audit(db, None, action, 'DENIED: unauthenticated')
                self.fail(401, 'Valid Bearer token required')
                return None
            if actor.role not in permitted:
                with connect(db_path) as db:
                    write_audit(db, actor.id, action, 'DENIED: insufficient role')
                self.fail(403, 'Insufficient permission')
                return None
            return actor

        def owner_check(self, actor: Principal, incident) -> bool:
            if actor.role in ('administrator', 'auditor'):
                return True
            if actor.role == 'employee':
                return actor.id == incident['reporter_id']
            if actor.role == 'analyst':
                return actor.id == incident['assigned_analyst_id']
            return False

        def deny_scope(self, actor: Principal, action: str):
            with connect(db_path) as db:
                write_audit(db, actor.id, action, 'DENIED: not owner or assignee')
            self.fail(403, 'Not authorized for this incident')

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == '/health':  # Responsible student: Amal Haddad
                return self.reply(200, {'status': 'ok'})
            if path == '/incidents':  # Responsible student: Lina Khoury
                actor = self.require({'administrator', 'auditor'}, 'GET /incidents')
                if actor is None:
                    return
                with connect(db_path) as db:
                    rows = db.execute('SELECT * FROM incidents ORDER BY id').fetchall()
                return self.reply(200, {'incidents': [dict(row) for row in rows]})
            match = re.fullmatch(r'/incidents/(\d+)', path)
            if match:  # Responsible student: Lina Khoury
                actor = self.require({'administrator', 'auditor', 'analyst', 'employee'}, 'GET /incidents/:id')
                if actor is None:
                    return
                with connect(db_path) as db:
                    row = db.execute('SELECT * FROM incidents WHERE id=?', (int(match[1]),)).fetchone()
                    if row is None:
                        return self.fail(404, 'Incident not found')
                    if not self.owner_check(actor, row):
                        return self.deny_scope(actor, 'GET /incidents/:id')
                    notes = db.execute('SELECT id, analyst_id, content, created_at FROM investigation_notes WHERE incident_id=?',
                                       (row['id'],)).fetchall()
                return self.reply(200, {'incident': dict(row), 'notes': [dict(note) for note in notes]})
            if path == '/audit-logs':  # Responsible student: Karim Daher
                actor = self.require({'administrator', 'auditor'}, 'GET /audit-logs')
                if actor is None:
                    return
                with connect(db_path) as db:
                    logs = db.execute('SELECT * FROM audit_logs ORDER BY id').fetchall()
                return self.reply(200, {'logs': [dict(log) for log in logs]})
            self.fail(404, 'Route not found')

        def do_POST(self):
            path = urlsplit(self.path).path
            if path == '/auth/login':  # Responsible student: Karim Daher
                body = self.body()
                if body is None or not isinstance(body.get('username'), str) or not isinstance(body.get('password'), str):
                    return self.fail(400, 'username and password are required')
                with connect(db_path) as db:
                    row = db.execute('SELECT * FROM users WHERE username=?', (body['username'],)).fetchone()
                    valid = bool(row and verify_password(body['password'], row['salt'], row['password_hash']))
                    write_audit(db, row['id'] if row else None, 'POST /auth/login', 'SUCCESS' if valid else 'DENIED: bad credentials')
                if not valid:
                    return self.fail(401, 'Invalid credentials')
                actor = Principal(row['id'], row['username'], row['role'])
                return self.reply(200, {'access_token': sessions.create(actor), 'token_type': 'Bearer', 'role': actor.role})
            if path == '/incidents':  # Responsible student: Lina Khoury
                actor = self.require({'administrator', 'employee'}, 'POST /incidents')
                if actor is None:
                    return
                body = self.body()
                required = ('title', 'description', 'category', 'severity', 'affected_asset')
                if body is None or any(not isinstance(body.get(key), str) or not body[key].strip() for key in required):
                    return self.fail(400, 'Required non-empty fields: ' + ', '.join(required))
                if body['severity'] not in SEVERITIES:
                    return self.fail(400, 'Invalid severity; use Low, Medium, High, or Critical')
                with connect(db_path) as db:
                    cursor = db.execute('''INSERT INTO incidents
                        (title,description,category,severity,affected_asset,reporter_id,status,created_at)
                        VALUES(?,?,?,?,?,?,?,?)''',
                        (body['title'].strip(), body['description'].strip(), body['category'].strip(),
                         body['severity'], body['affected_asset'].strip(), actor.id, 'Open', utc_now()))
                    write_audit(db, actor.id, 'POST /incidents', 'SUCCESS')
                    incident_id = cursor.lastrowid
                return self.reply(201, {'id': incident_id, 'status': 'Open'})
            match = re.fullmatch(r'/incidents/(\d+)/notes', path)
            if match:  # Responsible student: Lina Khoury
                actor = self.require({'administrator', 'analyst'}, 'POST /incidents/:id/notes')
                if actor is None:
                    return
                body = self.body()
                if body is None or not isinstance(body.get('content'), str) or not body['content'].strip():
                    return self.fail(400, 'content must be a non-empty string')
                with connect(db_path) as db:
                    row = db.execute('SELECT * FROM incidents WHERE id=?', (int(match[1]),)).fetchone()
                    if row is None:
                        return self.fail(404, 'Incident not found')
                    if actor.role == 'analyst' and row['assigned_analyst_id'] != actor.id:
                        return self.deny_scope(actor, 'POST /incidents/:id/notes')
                    cur = db.execute('INSERT INTO investigation_notes(incident_id,analyst_id,content,created_at) VALUES(?,?,?,?)',
                                     (row['id'], actor.id, body['content'].strip(), utc_now()))
                    write_audit(db, actor.id, 'POST /incidents/:id/notes', 'SUCCESS')
                    note_id = cur.lastrowid
                return self.reply(201, {'note_id': note_id})
            self.fail(404, 'Route not found')

        def do_PUT(self):
            path = urlsplit(self.path).path
            match = re.fullmatch(r'/incidents/(\d+)/(assign|status)', path)
            if not match:
                return self.fail(404, 'Route not found')
            incident_id, action = int(match[1]), match[2]
            actor = self.require({'administrator'} if action == 'assign' else {'administrator', 'analyst'},
                                 'PUT /incidents/:id/' + action)
            if actor is None:
                return
            body = self.body()
            if body is None:
                return self.fail(400, 'Request must be a JSON object')
            with connect(db_path) as db:
                incident = db.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
                if incident is None:
                    return self.fail(404, 'Incident not found')
                if action == 'assign':  # Responsible student: Amal Haddad
                    username = body.get('analyst_username')
                    if not isinstance(username, str) or not username:
                        return self.fail(400, 'analyst_username is required')
                    analyst = db.execute('SELECT * FROM users WHERE username=? AND role=?',
                                         (username, 'analyst')).fetchone()
                    if analyst is None:
                        return self.fail(400, 'Target user must have the analyst role')
                    db.execute('UPDATE incidents SET assigned_analyst_id=? WHERE id=?', (analyst['id'], incident_id))
                    write_audit(db, actor.id, 'PUT /incidents/:id/assign', 'SUCCESS')
                    return self.reply(200, {'id': incident_id, 'assigned_analyst': username})
                # Responsible student: Lina Khoury
                if actor.role == 'analyst' and incident['assigned_analyst_id'] != actor.id:
                    return self.deny_scope(actor, 'PUT /incidents/:id/status')
                target = body.get('status')
                current = incident['status']
                if not isinstance(target, str) or target not in STATUSES:
                    return self.fail(400, 'Unknown status')
                if STATUSES.index(target) != STATUSES.index(current) + 1:
                    return self.fail(409, f'Invalid transition: {current} -> {target}')
                resolved_at = utc_now() if target == 'Resolved' else incident['resolved_at']
                db.execute('UPDATE incidents SET status=?, resolved_at=? WHERE id=?',
                           (target, resolved_at, incident_id))
                write_audit(db, actor.id, 'PUT /incidents/:id/status', 'SUCCESS')
            return self.reply(200, {'id': incident_id, 'status': target})

    return HTTPServer((host, port), Handler)
