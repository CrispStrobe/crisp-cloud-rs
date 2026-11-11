"""Tests of the gate itself: a broken probe must never produce a green run."""
import copy
import unittest
from compare import compare


class ComparisonTest(unittest.TestCase):
    def setUp(self):
        self.cases = [{'id': 'sample', 'op': 'filen.chunk', 'expected': {'length': 1, 'sha256': 'oracle'}}]
        result = {'schema': 1, 'results': {'sample': {'status': 'ok', 'value': self.cases[0]['expected']}}}
        self.outputs = {'dart': copy.deepcopy(result), 'rust': copy.deepcopy(result)}

    def test_independent_oracle_required_even_when_engines_agree(self):
        for output in self.outputs.values():
            output['results']['sample']['value']['sha256'] = 'same-bug'
        self.assertEqual(len(compare(self.cases, self.outputs)['failures']), 2)

    def test_missing_extra_panic_and_false_rejection_fail(self):
        for result in [{}, {'extra': {}}, {'sample': {'status': 'panicked'}}, {'sample': {'status': 'rejected'}}]:
            with self.subTest(result=result):
                self.outputs['rust']['results'] = result
                self.assertFalse(compare(self.cases, self.outputs)['passed'])

    def test_reviewed_difference_is_exact_and_blocks_promotion(self):
        self.cases[0].update(engine_expected={'dart': {'status': 'rejected'}}, known_difference='reviewed')
        self.outputs['dart']['results']['sample'] = {'status': 'rejected'}
        report = compare(self.cases, self.outputs)
        self.assertTrue(report['passed'])
        self.assertFalse(report['promotion_ready'])
        self.assertFalse(compare(self.cases, self.outputs, strict=True)['passed'])
        self.outputs['dart']['results']['sample'] = {'status': 'panicked'}
        self.assertFalse(compare(self.cases, self.outputs)['passed'])

    def test_unknown_operation_and_duplicate_ids_fail(self):
        with self.assertRaises(ValueError):
            compare(self.cases * 2, self.outputs)
        self.cases[0]['op'] = 'unimplemented'
        with self.assertRaises(ValueError):
            compare(self.cases, self.outputs)

    def test_equal_valid_results_pass_promotion(self):
        self.assertTrue(compare(self.cases, self.outputs, strict=True)['promotion_ready'])


if __name__ == '__main__':
    unittest.main()
