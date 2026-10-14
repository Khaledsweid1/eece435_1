"""Initialize four fictional users for the local demonstration."""
import os
from .storage import seed_users


def main():
    password = os.getenv('DEMO_PASSWORD')
    if not password:
        raise SystemExit('Set DEMO_PASSWORD (12+ characters) before running this module.')
    db_path = os.getenv('DATABASE_PATH', 'data/demo.sqlite3')
    seed_users(db_path, password)
    print('Demo accounts initialized in', db_path)
    print('Usernames: demo_admin, demo_analyst, demo_employee, demo_auditor')


if __name__ == '__main__':
    main()
