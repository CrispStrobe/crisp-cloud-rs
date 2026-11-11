"""Strict result comparison: missing cases, panics and stale allowances fail.

Each reviewed difference has an exact per-engine result. It is still reported
as a compatibility gap, and --strict makes any such gap fail the promotion gate.
"""
import json
from pathlib import Path

OPS = {'filen.login', 'filen.metadata.encrypt', 'filen.metadata.decrypt',
       'filen.chunk', 'filen.chunk.decrypt', 'filen.chunk.encrypt.reject', 'internxt.password',
       'internxt.text.decrypt', 'internxt.text.roundtrip', 'internxt.key',
       'internxt.ctr', 'internxt.range', 'internxt.ctr.decrypt', 'internxt.stream',
       'filen.mock.list', 'internxt.mock.list', 'internxt.mock.mutate'}


def expected_result(case):
    value = case['expected']
    return value if isinstance(value, dict) and value.get('status') == 'rejected' else {'status': 'ok', 'value': value}


def compare(cases, outputs, strict=False):
    ids = [c['id'] for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate fixture IDs')
    if any(c['op'] not in OPS for c in cases):
        raise ValueError('Unknown fixture operation')
    failures, gaps = [], []
    for engine, output in outputs.items():
        if output.get('schema') != 1 or set(output.get('results', {})) != set(ids):
            failures.append(f'{engine}: missing, extra or invalid result set')
    for case in cases:
        actual = {}
        for engine, output in outputs.items():
            value = output.get('results', {}).get(case['id'])
            actual[engine] = value
            expected = case.get('engine_expected', {}).get(engine, expected_result(case))
            if value != expected:
                failures.append(f"{case['id']} [{engine}]: expected {expected!r}, got {value!r}")
        overrides = case.get('engine_expected', {})
        if overrides:
            if not case.get('known_difference'):
                raise ValueError('Every difference requires an explanation')
            if all(v == expected_result(case) for v in overrides.values()):
                raise ValueError('Stale compatibility allowance')
            gaps.append({'id': case['id'], 'reason': case['known_difference'], 'results': actual})
        elif len({json.dumps(v, sort_keys=True) for v in actual.values()}) > 1:
            failures.append(f"{case['id']}: engines disagree")
    return {'schema': 1, 'cases': len(cases), 'engines': list(outputs),
            'failures': failures, 'known_gaps': gaps,
            'promotion_ready': not failures and not gaps,
            'passed': not failures and (not strict or not gaps)}


def write_report(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    lines = ['# Dart / Rust provider conformance', '',
             f"Cases: {report['cases']}. Unexpected failures: {len(report['failures'])}. "
             f"Reviewed compatibility gaps: {len(report['known_gaps'])}.", '',
             'Default-promotion gate: ' + ('PASS' if report['promotion_ready'] else 'BLOCKED'), '',
             'A green regression run preserves reviewed differences; it does not certify engine interchangeability.', '']
    if report['known_gaps']:
        lines += ['| Case | Difference |', '| --- | --- |']
        lines += [f"| `{gap['id']}` | {gap['reason']} |" for gap in report['known_gaps']]
    if report['failures']:
        lines += ['', '## Unexpected failures', ''] + ['- ' + f for f in report['failures']]
    (directory / 'report.md').write_text('\n'.join(lines) + '\n')
