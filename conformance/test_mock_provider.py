import json
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from mock_provider import MockProvider, TOKEN, cases


class MockOracleTest(unittest.TestCase):
    def fixture(self, identifier):
        return next(c for c in cases() if c['id'] == identifier)

    def request(self, base, path, method='GET', body=None, token=TOKEN):
        request = Request(base + path, method=method,
                          data=None if body is None else json.dumps(body).encode(),
                          headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        return urlopen(request, timeout=5)

    def test_wire_oracle_accepts_correct_listing(self):
        case = self.fixture('internxt.mock.list.unicode')
        with MockProvider([case]) as server:
            base = server.for_engine({'cases': [case]}, 'rust')['cases'][0]['base_url']
            for kind in ['folders', 'files']:
                with self.request(base, '/folders/content/root/' + kind + '?offset=0&limit=50&sort=plainName&direction=ASC') as response:
                    self.assertEqual(len(json.load(response)['result']), 2)
            self.assertEqual(server.verify(['rust']), [])

    def test_wrong_sort_auth_and_duplicate_page_cannot_pass(self):
        case = self.fixture('internxt.mock.list.unicode')
        with MockProvider([case]) as server:
            base = server.for_engine({'cases': [case]}, 'rust')['cases'][0]['base_url']
            for _ in range(2):
                self.request(base, '/folders/content/root/files?offset=0&limit=50&sort=plainName&order=ASC', token='wrong').close()
            errors = server.verify(['rust'])
            self.assertTrue(any('authentication' in e for e in errors))
            self.assertTrue(any('sort parameters' in e for e in errors))
            self.assertTrue(any('pagination offsets' in e for e in errors))

    def test_mutation_payload_and_replay_are_checked(self):
        case = self.fixture('internxt.mock.trash.200')
        with MockProvider([case]) as server:
            base = server.for_engine({'cases': [case]}, 'dart')['cases'][0]['base_url']
            with self.assertRaises(HTTPError):
                self.request(base, '/storage/trash/add', method='POST', body={'items': []})
            self.request(base, '/storage/trash/add', method='POST', body={'items': [{'uuid': 'file', 'type': 'file'}]}).close()
            errors = server.verify(['dart'])
            self.assertTrue(any('payload' in e for e in errors))
            self.assertTrue(any('replayed' in e for e in errors))

    def test_forbidden_mutation_stays_forbidden(self):
        case = self.fixture('internxt.mock.move.403')
        with MockProvider([case]) as server:
            base = server.for_engine({'cases': [case]}, 'rust')['cases'][0]['base_url']
            with self.assertRaises(HTTPError) as result:
                self.request(base, '/files/file', method='PATCH', body={'destinationFolder': 'destination'})
            self.assertEqual(result.exception.code, 403)
            self.assertEqual(server.verify(['rust']), [])


if __name__ == '__main__':
    unittest.main()
