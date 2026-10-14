"""Run with: PYTHONPATH=src python -m incident_demo"""
import os
from .api import create_server


def main():
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', '8765'))
    db_path = os.getenv('DATABASE_PATH', 'data/demo.sqlite3')
    server = create_server(host, port, db_path)
    print(f'Example API at http://{host}:{port} (Ctrl+C to stop)', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
