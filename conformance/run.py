"""Run actual SDKs against independent vectors, then cross-decrypt exports."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from compare import compare, write_report
from generate_vectors import build

ROOT = Path(__file__).resolve().parent


def command(argv, cwd, env=None, timeout=600):
    subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=timeout)


def configure(args):
    overrides = {}
    for package, path in [('filen_client', args.dart_filen), ('internxt_client', args.dart_internxt)]:
        if path:
            overrides[package] = {'path': str(Path(path).resolve())}
    if args.pointycastle:
        overrides['pointycastle'] = args.pointycastle
    (ROOT / 'dart/pubspec_overrides.yaml').write_text(json.dumps({'dependency_overrides': overrides}, indent=2))
    manifest = (ROOT / 'rust/Cargo.toml').read_text()
    for package, path in [('crisp-filen', args.rust_filen), ('crisp-internxt', args.rust_internxt)]:
        if path:
            import re
            manifest = re.sub(rf'{package} = \{{path="[^"]+"\}}',
                              lambda _: package + ' = {path=' + json.dumps(str(Path(path).resolve())) + '}', manifest)
    # Isolated workspace allows testing the Sorter copies without modifying
    # production dependencies. Restore the manifest even after a failed run.
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ['dart-filen', 'dart-internxt', 'rust-filen', 'rust-internxt', 'pointycastle']:
        parser.add_argument('--' + arg)
    parser.add_argument('--strict', action='store_true', help='fail on reviewed gaps too (default-promotion gate)')
    args = parser.parse_args()
    results = ROOT / 'results'
    results.mkdir(exist_ok=True)
    original_manifest = (ROOT / 'rust/Cargo.toml').read_text()
    try:
        (ROOT / 'rust/Cargo.toml').write_text(configure(args))
        fixtures = build()
        (ROOT / 'vectors.json').write_text(json.dumps(fixtures, ensure_ascii=False, indent=2) + '\n')
        command(['dart', 'pub', 'get'], ROOT / 'dart')
        command(['cargo', 'build', '--manifest-path', 'Cargo.toml'], ROOT / 'rust')
        rust = ROOT / 'rust/target/debug/provider-conformance-probe'
        engines = [('rust', [str(rust)], None)] + [
            ('dart' + suffix, ['dart', 'run', 'bin/probe.dart'], dict(os.environ, FILEN_TEST_BACKEND=backend))
            for suffix, backend in [('', 'cryptography'), ('-pointycastle', 'pointycastle')]]
        outputs = {}
        for name, argv, env in engines:
            path = results / (name + '.json')
            command(argv + [str(ROOT / 'vectors.json'), str(path)], ROOT / 'dart', env)
            outputs[name] = json.loads(path.read_text())
        # Both software AES-GCM backends must meet the same Dart expectations.
        for case in fixtures['cases']:
            if 'dart' in case.get('engine_expected', {}):
                case['engine_expected']['dart-pointycastle'] = case['engine_expected']['dart']
        report = compare(fixtures['cases'], outputs, strict=args.strict)
        cross_count = 0
        for producer, output in outputs.items():
            exports = output['exports']
            # Do not allow an implementation to skip its encryption checks.
            required = {c['id'] for c in fixtures['cases'] if c.get('export') and
                        c.get('engine_expected', {}).get(producer, {}).get('status') != 'rejected'}
            if {c['id'] for c in exports} != required:
                report['failures'].append(producer + ': incomplete encryption exports')
            path = results / (producer + '-exports.json')
            path.write_text(json.dumps({'cases': exports}))
            for consumer, argv, env in engines:
                if consumer == producer:
                    continue
                target = results / (producer + '-to-' + consumer + '.json')
                command(argv + [str(path), str(target)], ROOT / 'dart', env)
                compared = compare(exports, {consumer: json.loads(target.read_text())})
                report['failures'] += [producer + ' -> ' + consumer + ': ' + f for f in compared['failures']]
                cross_count += len(exports)
        report['cross_decryptions'] = cross_count
        report['promotion_ready'] = not report['failures'] and not report['known_gaps']
        report['passed'] = not report['failures'] and (not args.strict or not report['known_gaps'])
        write_report(report, results)
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary, 'a') as stream:
                stream.write((results / 'report.md').read_text())
        print(f"{report['cases']} cases; {cross_count} cross-decryptions; "
              f"{len(report['failures'])} failures; {len(report['known_gaps'])} reviewed gaps")
        return 0 if report['passed'] else 1
    finally:
        (ROOT / 'rust/Cargo.toml').write_text(original_manifest)


if __name__ == '__main__':
    sys.exit(main())
