"""Tests against a real local HTTP server and disposable SQLite database."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from incident_demo.api import create_server
from incident_demo.storage import seed_users

TEST_PASSWORD = 'local-test-pass-123'


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        db_path = str(Path(cls.directory.name) / 'test.sqlite3')
        seed_users(db_path, TEST_PASSWORD)
        cls.server = create_server('127.0.0.1', 0, db_path)
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.directory.cleanup()

    def request(self, method, path, body=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = Request(self.url + path,
                          data=json.dumps(body).encode() if body is not None else None,
                          headers=headers, method=method)
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def login(self, username):
        code, result = self.request('POST', '/auth/login',
                                    {'username': username, 'password': TEST_PASSWORD})
        self.assertEqual(code, 200)
        return result['access_token']

    def create_incident(self, token):
        return self.request('POST', '/incidents', {
            'title': 'Suspicious sign-in', 'description': 'Employee reported unusual sign-in',
            'category': 'Account compromise', 'severity': 'High', 'affected_asset': 'LAPTOP-01',
        }, token)

    def test_login_and_bad_password(self):
        code, data = self.request('POST', '/auth/login',
                                  {'username': 'demo_employee', 'password': 'incorrect'})
        self.assertEqual(code, 401)
        self.assertEqual(data['status'], 'error')
        self.assertTrue(self.login('demo_employee'))

    def test_input_validation_and_real_creation(self):
        employee = self.login('demo_employee')
        code, _ = self.request('POST', '/incidents', {'title': 'Only one field'}, employee)
        self.assertEqual(code, 400)
        code, data = self.create_incident(employee)
        self.assertEqual(code, 201)
        code, details = self.request('GET', f"/incidents/{data['id']}", token=employee)
        self.assertEqual(code, 200)
        self.assertEqual(details['incident']['status'], 'Open')

    def test_rbac_and_audit_denial(self):
        employee = self.login('demo_employee')
        auditor = self.login('demo_auditor')
        code, _ = self.request('GET', '/incidents', token=employee)
        self.assertEqual(code, 403)
        code, data = self.request('GET', '/audit-logs', token=auditor)
        self.assertEqual(code, 200)
        self.assertTrue(any(row['outcome'].startswith('DENIED') for row in data['logs']))

    def test_assignment_and_status_transition(self):
        employee = self.login('demo_employee')
        admin = self.login('demo_admin')
        analyst = self.login('demo_analyst')
        code, incident = self.create_incident(employee)
        self.assertEqual(code, 201)
        path = f"/incidents/{incident['id']}"
        code, _ = self.request('PUT', path + '/status', {'status': 'Closed'}, analyst)
        self.assertEqual(code, 403)  # unassigned analyst cannot edit
        code, _ = self.request('PUT', path + '/assign', {'analyst_username': 'demo_analyst'}, admin)
        self.assertEqual(code, 200)
        code, _ = self.request('PUT', path + '/status', {'status': 'Closed'}, analyst)
        self.assertEqual(code, 409)  # cannot skip required lifecycle
        code, data = self.request('PUT', path + '/status', {'status': 'Under Investigation'}, analyst)
        self.assertEqual(code, 200)
        self.assertEqual(data['status'], 'Under Investigation')
        code, _ = self.request('POST', path + '/notes', {'content': 'Reviewed account logs'}, analyst)
        self.assertEqual(code, 201)

    def test_missing_authorization(self):
        code, data = self.request('GET', '/incidents')
        self.assertEqual(code, 401)
        self.assertIn('message', data)


if __name__ == '__main__':
    unittest.main()
