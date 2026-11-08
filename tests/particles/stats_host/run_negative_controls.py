#!/usr/bin/env python3
"""Build generated-only mutations and require fresh, completed assertion failures.

Configure/compiler errors, signals, sanitizer diagnostics, incomplete/skipped
runs, stale/missing XML, and the wrong selected test set are rejected.
"""
import argparse
import hashlib
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

CONTROLS = {
    'segments_as_vertices': (
        'StatsHost.TrailPressureCountsSegmentsNotVertices:'
        'StatsHost.PartialTailDropsOnlyRemainingSegments'
    ),
    'omit_partial_capacity': 'StatsHost.PartialTrailInitializationRecordsEachSuccessfulInsert',
    'clear_ends_session': 'StatsHost.ReplayStyleClearPreservesSessionAndAllowsContinuedCollection',
    'clear_resets_session': 'StatsHost.ReplayStyleClearPreservesSessionAndAllowsContinuedCollection',
    'end_after_clear': 'StatsHost.TeardownIncludesFinalDrainThenLogsBeforeDestruction',
    'end_before_drain': 'StatsHost.TeardownIncludesFinalDrainThenLogsBeforeDestruction',
    'omit_inherited_occupancy': 'StatsHost.NextSessionSeedsInheritedUnavailableAndExhaustedPools',
    'omit_summary_log': 'StatsHost.SessionLoggerPublishesOnceWithNamedMetrics',
}
SANITIZER_DIAGNOSTIC = re.compile(
    r'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|'
    r'ThreadSanitizer|HWAddressSanitizer|Sanitizer:DEADLYSIGNAL|runtime error:',
    re.IGNORECASE,
)


def validate_result(name, selected, run, xml, log):
    if run.returncode != 1:
        raise RuntimeError(f'{name}: expected assertion exit 1, got {run.returncode}')
    output = log.read_text()
    if SANITIZER_DIAGNOSTIC.search(output):
        raise RuntimeError(f'{name}: sanitizer diagnostic is not a valid assertion control')
    expected = set(selected.split(':'))
    completed = re.findall(
        r'^\[==========\] (\d+) tests? from \d+ test suites? ran\.', output, re.MULTILINE
    )
    if completed != [str(len(expected))]:
        raise RuntimeError(f'{name}: missing/incorrect GTest completion summary: {completed}')
    if '[----------] Global test environment tear-down' not in output:
        raise RuntimeError(f'{name}: test environment did not complete teardown')
    # The caller removed this exact path immediately before execution. Missing
    # fresh XML must fail here, never fall back to a previous report.
    tree = ET.parse(xml).getroot()
    if tree.tag != 'testsuites':
        raise RuntimeError(f'{name}: unexpected XML root {tree.tag}')
    tests = int(tree.attrib['tests'])
    failures = int(tree.attrib['failures'])
    errors = int(tree.attrib['errors'])
    if tests != len(expected) or failures != len(expected) or errors:
        raise RuntimeError(f'{name}: incorrect assertion result: {tree.attrib}')
    if int(tree.attrib.get('disabled', '0')) or tree.findall('.//skipped') or tree.findall('.//error'):
        raise RuntimeError(f'{name}: skipped/disabled/error outcome is not a valid control')
    cases = tree.findall('./testsuite/testcase')
    actual = [f"{case.attrib['classname']}.{case.attrib['name']}" for case in cases]
    if len(cases) != len(expected) or set(actual) != expected:
        raise RuntimeError(f'{name}: wrong or duplicate selected tests: {actual}')
    for case in cases:
        if case.attrib.get('status') != 'run' or case.attrib.get('result') != 'completed':
            raise RuntimeError(f'{name}: incomplete testcase: {case.attrib}')
        if not case.findall('failure'):
            raise RuntimeError(f'{name}: selected test did not produce an assertion failure')
    return dict(
        control=name, exit_code=run.returncode, tests=tests, failed_tests=failures,
        errors=errors, completed_tests=len(cases), selected_tests=sorted(actual),
        filter=selected, log=str(log), fresh_xml_sha256=hashlib.sha256(xml.read_bytes()).hexdigest(),
        sanitizer_diagnostics_found=False,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cmake', required=True)
    parser.add_argument('--source-dir', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--gtest-library-dir', required=True)
    args = parser.parse_args()
    root = args.build_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    summary = root / 'summary.json'
    summary.unlink(missing_ok=True)
    results = []
    for name, selected in CONTROLS.items():
        build = root / name
        build.mkdir(exist_ok=True)
        commands = [
            [args.cmake, '-S', str(args.source_dir), '-B', str(build),
             f'-DFAF_GTEST_LIBRARY_DIR={args.gtest_library_dir}', f'-DFAF_STATS_NEGATIVE_CONTROL={name}'],
            [args.cmake, '--build', str(build), '-j2'],
        ]
        for command, filename in zip(commands, ['configure.log', 'build.log']):
            with (build / filename).open('w') as stream:
                subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
        xml = build / 'results.xml'
        log = build / 'test.log'
        xml.unlink(missing_ok=True)
        command = [str(build / 'particle_stats_host'), f'--gtest_filter={selected}', f'--gtest_output=xml:{xml}']
        with log.open('w') as stream:
            run = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
        result = validate_result(name, selected, run, xml, log)
        results.append(result)
        print(json.dumps(result), flush=True)
    summary.write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
