import os
import tempfile
import unittest

class DNSInspectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['DB_PATH'] = os.path.join(self.tmp.name, 'inspector.db')
        os.environ['DISABLE_BACKGROUND_SERVICES'] = '1'
        import app
        self.app = app.app
        self.app.config.update(TESTING=True)

    def tearDown(self):
        self.tmp.cleanup()
        for key in ('DB_PATH','DISABLE_BACKGROUND_SERVICES'):
            os.environ.pop(key, None)

    def test_health_and_empty_state(self):
        with self.app.test_client() as c:
            self.assertEqual(c.get('/health').status_code, 200)
            self.assertEqual(c.get('/').status_code, 200)

    def test_ping_api_is_registered(self):
        rules = {r.rule for r in self.app.url_map.iter_rules()}
        self.assertIn('/api/ip/ping', rules)
        self.assertIn('/api/ip/ping/status', rules)

    def test_dev_ui_assets_present(self):
        self.assertTrue(os.path.exists('/tmp/dns16/static/favicon-dev.svg'))

    def test_schema_uses_wal_and_indexes(self):
        from dnsinspector.db import db_connect, init_db
        init_db()
        with db_connect(os.environ['DB_PATH']) as c:
            self.assertEqual(c.execute('PRAGMA journal_mode').fetchone()[0].lower(), 'wal')
            names = {r[1] for r in c.execute("SELECT type,name FROM sqlite_master WHERE type='index'")}
            self.assertIn('idx_domains_requests', names)

    def test_busy_timeout_allows_competing_writers(self):
        from dnsinspector.db import db_connect, init_db
        init_db()
        with db_connect(os.environ['DB_PATH']) as c:
            self.assertEqual(c.execute('PRAGMA busy_timeout').fetchone()[0], 30000)

if __name__ == '__main__':
    unittest.main()
