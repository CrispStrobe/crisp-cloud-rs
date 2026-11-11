"""Run actual SDKs against independent vectors, then cross-decrypt exports."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from compare import compare, write_report
from generate_vectors import build
from mock_provider import MockProvider, cases as mock_cases

ROOT = Path(__file__).resolve().parent


def command(argv, cwd, env=None, timeout=600):
    subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=timeout)


def configure(args):
    overrides = {}
    for package, path in [('filen_client', args.dart_filen), ('internxt_client', args.dart_internxt)]:
        if path:
            overrides[package] = {'path': str(Path(path).resolve())}
    if args.published_internxt:
        if args.dart_internxt:
            raise ValueError('Choose a Dart Internxt source directory or a published version')
        overrides['internxt_client'] = args.published_internxt
    if args.pointycastle:
        overrides['pointycastle'] = args.pointycastle
    if args.dart_pg:
        overrides['dart_pg'] = args.dart_pg
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
    for arg in ['dart-filen', 'dart-internxt', 'rust-filen', 'rust-internxt', 'pointycastle', 'dart-pg', 'published-internxt', 'prebuilt']:
        parser.add_argument('--' + arg)
    parser.set_defaults(pointycastle='4.0.0', dart_pg='2.1.0')
    parser.add_argument('--strict', action='store_true', help='fail on reviewed gaps too (default-promotion gate)')
    args = parser.parse_args()
    results = ROOT / 'results'
    results.mkdir(exist_ok=True)
    original_manifest = (ROOT / 'rust/Cargo.toml').read_text()
    try:
        (ROOT / 'rust/Cargo.toml').write_text(configure(args))
        fixtures = build()
        fixtures['cases'] += mock_cases()
        (ROOT / 'vectors.json').write_text(json.dumps(fixtures, ensure_ascii=False, indent=2) + '\n')
        if args.prebuilt:
            rust = Path(args.prebuilt).resolve() / 'rust-probe'
            dart = Path(args.prebuilt).resolve() / 'dart-probe'
        else:
            command(['dart', 'pub', 'get'], ROOT / 'dart')
            dart = results / 'dart-probe'
            command(['dart', 'compile', 'exe', 'bin/probe.dart', '-o', str(dart)], ROOT / 'dart')
            command(['cargo', 'build', '--manifest-path', 'Cargo.toml'], ROOT / 'rust')
            rust = ROOT / 'rust/target/debug/provider-conformance-probe'
            import shutil
            shutil.copy2(rust, results / 'rust-probe')
        engines = [('rust', [str(rust)], None)] + [
            ('dart' + suffix, [str(dart)], dict(os.environ, FILEN_TEST_BACKEND=backend))
            for suffix, backend in [('', 'cryptography'), ('-pointycastle', 'pointycastle'), ('-native', 'native')]]
        outputs = {}
        with MockProvider(fixtures['cases']) as server:
            for name, argv, env in engines:
                path = results / (name + '.json')
                input_path = ROOT / 'generated' / (name + '-input.json')
                source = server.for_engine(fixtures, name)
                for case in source['cases']:
                    if 'encrypted_file' in case:
                        case['encrypted_file'] = case['encrypted_file'].removeprefix('generated/')
                input_path.write_text(json.dumps(source))
                command(argv + [str(input_path), str(path)], ROOT / 'dart', env)
                outputs[name] = json.loads(path.read_text())
            wire_failures = server.verify([name for name, _, _ in engines])
            (results / 'mock-requests.json').write_text(json.dumps(server.requests, indent=2, ensure_ascii=False))
        # Both software AES-GCM backends must meet the same Dart expectations.
        for case in fixtures['cases']:
            if 'dart' in case.get('engine_expected', {}):
                case['engine_expected']['dart-pointycastle'] = case['engine_expected']['dart']
                case['engine_expected']['dart-native'] = case['engine_expected']['dart']
        report = compare(fixtures['cases'], outputs, strict=args.strict)
        report['failures'] += wire_failures
        report['mock_cases'] = len(mock_cases())
        report['native_backend'] = outputs['dart-native'].get('actual_backend')
        if sys.platform.startswith('linux') and report['native_backend'] != 'openssl':
            report['failures'].append('Linux native AES-GCM tests fell back instead of loading OpenSSL')
        cross_count = 0
        for producer, output in outputs.items():
            exports = output['exports']
            # Do not allow an implementation to skip its encryption checks.
            required = {c['id'] for c in fixtures['cases'] if c.get('export') and
                        c.get('engine_expected', {}).get(producer, {}).get('status') != 'rejected'}
            if {c['id'] for c in exports} != required or len(exports) != len(required):
                report['failures'].append(producer + ': incomplete encryption exports')
            original = {c['id']: c for c in fixtures['cases']}
            for case in exports:
                if case.get('expected') != original.get(case['id'], {}).get('expected'):
                    raise ValueError('Encryption export changed its oracle')
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
