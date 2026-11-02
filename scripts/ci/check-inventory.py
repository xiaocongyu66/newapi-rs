#!/usr/bin/env python3
"""Actions-only, read-only upstream inventory audit. No Go source is executed."""
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import subprocess
import sys

SHA = "17970da4571e81308f176a0e61a38276e5771606"
BASE = "apps/api/internal/transport/compose"
ALIASES = dict(A="register_api.go", C="register_channels.go", Z="register_authz.go",
               D="register_dashboard.go", R="register_relay.go", V="register_video.go",
               DEV="register_dev_autologin.go")
VERBS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE"
STRING = r'"(?:[^"\\]|\\.)*"'
# Preserve strings and newlines; remove comments, including commented registrations.
LEX = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]*`|\'(?:[^\'\\]|\\.)*\'|//[^\n]*|/\*[\s\S]*?\*/')


def clean(text):
    return LEX.sub(lambda m: re.sub(r'[^\n]', ' ', m[0])
                   if m[0].startswith(('//', '/*')) else m[0], text)


def rows(text):
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith('|'):
            yield n, [x.strip().strip('`') for x in line.strip('|').split('|')]


def join(base, relative):
    if not relative:
        return base
    result = posixpath.normpath(base.rstrip('/') + '/' + relative.lstrip('/'))
    if relative.endswith('/') and not result.endswith('/'):
        result += '/'
    return result


class Audit:
    def __init__(self, source, docs):
        self.source, self.docs = source, docs
        self.errors, self.unknown, self.routes = [], [], []
        self.hashes, self.files, self.functions = {}, {}, {}

    def read(self, root, name):
        p = root / name
        raw = p.read_bytes()
        self.hashes[str(p.relative_to(root))] = hashlib.sha256(raw).hexdigest()
        return raw.decode('utf-8')

    def issue(self, message):
        self.errors.append(message)

    def load_routes(self):
        for p in sorted((self.source / BASE).glob('*.go')):
            if p.name.endswith('_test.go'):
                continue
            text = clean(self.read(self.source, f'{BASE}/{p.name}'))
            self.files[p.name] = text
            for m in re.finditer(r'^func (\w+)\((\w+) contract\.(?:Engine|Routes)\) \{', text, re.M):
                # A top-level closing brace terminates these controlled functions.
                end = re.search(r'^}', text[m.end():], re.M)
                if text[m.end():].startswith('}'):
                    self.functions.setdefault(m[1], []).append((p.name, m[2], '', text[:m.end()].count('\n') + 1))
                    continue
                if end is None:
                    raise ValueError(f'unclosed function {p.name}:{m[1]}')
                body = text[m.end():m.end() + end.start()]
                self.functions.setdefault(m[1], []).append((p.name, m[2], body, text[:m.end()].count('\n') + 1))

    def walk(self, name, prefix, group, dev=False, chain=()):
        if name in chain:
            raise ValueError(f'recursive route helper {name}')
        choices = self.functions.get(name, [])
        if name == 'registerDevAutoLogin':
            suffix = 'register_dev_autologin.go' if dev else 'register_dev_autologin_stub.go'
            choices = [x for x in choices if x[0] == suffix]
        if len(choices) != 1:
            self.unknown.append(f'route helper unresolved: {name}')
            return
        filename, parameter, body, start = choices[0]
        env = {parameter: prefix}
        for offset, line in enumerate(body.splitlines()):
            line_no = start + offset
            s = line.strip()
            if not s:
                continue
            g = re.fullmatch(r'(\w+) := (\w+)\.Group\((' + STRING + r')\)', s)
            if g:
                if g[2] not in env or g[1] in env:
                    self.unknown.append(f'{filename}:{line_no}: group scope/reassignment')
                else:
                    env[g[1]] = join(env[g[2]], json.loads(g[3]))
                continue
            r = re.match(r'(\w+)\.(' + VERBS + r')\((' + STRING + r')\s*[,)]', s)
            if r:
                if r[1] not in env:
                    self.unknown.append(f'{filename}:{line_no}: unknown receiver {r[1]}')
                else:
                    self.routes.append(dict(group=group, method=r[2], path=join(env[r[1]], json.loads(r[3])),
                                            file=filename, line=line_no, dev=dev))
                continue
            helper = re.fullmatch(r'(\w+)\((\w+)\)', s)
            if helper and helper[2] in env:
                self.walk(helper[1], env[helper[2]], group, dev, chain + (name,))
                continue
            if '.Handle(' in s and filename == 'register_channels.go':
                if s != 'channelRoute.Handle(route.method, route.path,':
                    self.unknown.append(f'{filename}:{line_no}: unsupported table dispatch')
                    continue
                self.channel_table(env.get('channelRoute'), group, dev)
                continue
            if re.search(r'\.(?:Group|Handle|Any|' + VERBS + r')\s*\(', s):
                self.unknown.append(f'{filename}:{line_no}: unsupported route syntax')

    def channel_table(self, prefix, group, dev):
        text = self.files['register_channels.go']
        if prefix is None or 'for _, route := range channelPermissionRoutes {' not in text:
            self.unknown.append('channel table receiver/iteration unresolved')
            return
        match = re.search(r'var channelPermissionRoutes = \[\]permissionRoute\{([\s\S]*?)^}', text, re.M)
        if not match:
            self.unknown.append('channel table missing')
            return
        for offset, line in enumerate(match[1].splitlines()):
            if not line.strip():
                continue
            m = re.fullmatch(r'\s*\{method: http.Method(Get|Post|Put|Patch|Delete|Head|Options), path: (' + STRING + r'), permission: policy\.\w+, handler: [\w.]+},\s*', line)
            n = text[:match.start(1)].count('\n') + 1 + offset
            if not m:
                self.unknown.append(f'register_channels.go:{n}: unsupported table row')
                continue
            self.routes.append(dict(group=group, method=m[1].upper(), path=join(prefix, json.loads(m[2])),
                                    file='register_channels.go', line=n, dev=dev))

    def compare_routes(self):
        text = self.read(self.docs, 'contracts-inventory.md')
        ledger = []
        for n, cells in rows(text):
            if cells and re.fullmatch(VERBS, cells[0]):
                if len(cells) < 6 or not re.match(r'P[1-9](?!\d)', cells[5]):
                    self.issue(f'contracts:{n}: missing/invalid migration phase')
                    continue
                ref = re.fullmatch(r'([A-Z]+):([\d,–-]+)', cells[4])
                if not ref or ref[1] not in ALIASES:
                    self.issue(f'contracts:{n}: unsupported source reference {cells[4]}')
                    continue
                # Comma refs denote helper call and registration; ranges start at registration.
                points = [int(x.split('–')[0].split('-')[0]) for x in ref[2].split(',')]
                source_lines = self.files[ALIASES[ref[1]]].splitlines()
                for point in points[:-1]:
                    if point < 1 or point > len(source_lines) or not re.fullmatch(r'\s*registerMjRouterGroup\(\w+\)\s*', source_lines[point - 1]):
                        self.issue(f'contracts:{n}: invalid helper-call reference {point}')
                ledger.append(dict(method=cells[0], path=cells[1], file=ALIASES[ref[1]],
                                   line=points[-1], phase=cells[5], ledger_line=n))
        if not ledger:
            self.issue('empty route ledger')
        key = lambda r: (r['method'], r['path'], r['file'], r['line'])
        actual = collections.Counter(key(r) for r in self.routes)
        expected = collections.Counter(key(r) for r in ledger)
        for k, count in (actual - expected).items():
            self.issue(f'source route missing ledger mapping ({count}): {k}')
        for k, count in (expected - actual).items():
            self.issue(f'ledger route has no matching source registration ({count}): {k}')
        for k, count in expected.items():
            if count > 1:
                self.issue(f'duplicate ledger registration: {k}')
        counts = {}
        for group in ('api', 'dashboard', 'relay', 'video'):
            snapshot = self.read(self.source, f'{BASE}/testdata/routes_{group}.txt')
            snap = collections.Counter(x.strip() for x in snapshot.splitlines() if x.strip())
            got = collections.Counter(f"{r['method']} {r['path']}" for r in self.routes if r['group'] == group and not r['dev'])
            counts[group] = sum(got.values())
            if not snap or got != snap:
                self.issue(f'{group} snapshot difference: missing={dict(snap-got)}, extra={dict(got-snap)}')
            if any(v > 1 for v in got.values()):
                self.issue(f'{group}: duplicate source method/path')
        coverage = self.read(self.docs, 'routes-coverage.md')
        found = set()
        for n, cells in rows(coverage):
            label = cells[0].lower() if cells else ''
            if label in counts:
                found.add(label)
                try:
                    reported = int(cells[8])
                except (ValueError, IndexError):
                    self.issue(f'routes-coverage:{n}: invalid count')
                    continue
                if reported != counts[label]:
                    self.issue(f'routes-coverage:{n}: {reported} != source {counts[label]}')
        if found != set(counts):
            self.issue('routes-coverage group summary incomplete')
        return dict(counts=counts, source=self.routes, ledger=ledger)

    def data_candidates(self):
        """Literal model/task candidates only; never certify dynamic execution coverage."""
        ledger = self.read(self.docs, 'data-jobs-inventory.md')
        table = list(rows(ledger))
        models, tasks = [], []
        for p in sorted((self.source / 'apps/api').rglob('*.go')):
            if p.name.endswith('_test.go'):
                continue
            text = clean(p.read_text())
            relative = str(p.relative_to(self.source))
            for m in re.finditer(r'\bMigration\{Model:\s*&([\w.]+)\{\},\s*Name:\s*(' + STRING + r')\}', text):
                model = m[1].split('.')[-1]
                hits = [n for n, c in table if len(c) >= 4 and c[0].split(' / ')[0] == model and re.search(r'P[1-9](?!\d)', c[2])]
                item = dict(model=model, file=relative, line=text[:m.start()].count('\n') + 1, ledger_rows=hits)
                models.append(item)
                if not hits:
                    self.issue(f'literal model lacks owner/phase table mapping: {item}')
            for m in re.finditer(r'\b(?:go\s+|RegisterSystemTaskHandler\s*\(|time\.(?:NewTicker|AfterFunc)\s*\()', text):
                tasks.append(dict(file=relative, line=text[:m.start()].count('\n') + 1, syntax=m[0]))
        self.unknown.extend([
            'Models: literal Migration candidates checked by model/owner/phase rows only; registration call containment, qualified type identity, direct AutoMigrate, native/dynamic SQL and actual schemas not certified.',
            'Jobs: go/handler/timer candidates enumerated; indirect launchers, Type() dispatch, init/build tags, lifecycle and per-entry ledger mapping remain UNDETERMINED.',
            'Routes: static assets/fallback, runtime method handling and middleware behavior are outside explicit-registration equality; no behavioral acceptance claimed.'
        ])
        return dict(literal_models=models, asynchronous_candidates=tasks, status='UNDETERMINED')


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        print('Refusing local execution: GitHub Actions only.', file=sys.stderr)
        return 3
    workspace = Path(os.environ['GITHUB_WORKSPACE'])
    output = Path(os.environ['RUNNER_TEMP']) / 'p0-inventory'
    output.mkdir(parents=True, exist_ok=True)
    audit = Audit(workspace / 'upstream-reference', workspace / 'migration/docs')
    report = dict(upstream_sha=SHA, target_sha=os.getenv('GITHUB_SHA'), run_id=os.getenv('GITHUB_RUN_ID'),
                  attempt=os.getenv('GITHUB_RUN_ATTEMPT'), environment=platform.platform(),
                  image_version=os.getenv('ImageVersion'), target_databases=['SQLite', 'PostgreSQL'],
                  status='ERROR', tests_executed=0, source_execution=False)
    try:
        actual_sha = subprocess.check_output(['git', '-C', str(audit.source), 'rev-parse', 'HEAD'], text=True).strip()
        if actual_sha != SHA:
            raise ValueError(f'upstream SHA mismatch: {actual_sha}')
        audit.load_routes()
        for group, func in [('api', 'SetApiRouter'), ('dashboard', 'SetDashboardRouter'),
                            ('relay', 'SetRelayRouter'), ('video', 'SetVideoRouter')]:
            audit.walk(func, '', group)
        # Only the conditional helper is added, not a second copy of all production routes.
        audit.walk('registerDevAutoLogin', '/api/user', 'dev', dev=True)
        report['routes'] = audit.compare_routes()
        route_unknown = list(audit.unknown)
        report['routes_status'] = 'FAIL' if audit.errors else ('UNDETERMINED' if route_unknown else 'PASS_STATIC_EXPLICIT_ONLY')
        report['data_jobs'] = audit.data_candidates()
        report['status'] = 'FAIL' if audit.errors else 'PARTIAL'
    except Exception as exc:
        audit.issue(f'{type(exc).__name__}: {exc}')
        report['status'] = 'ERROR'
    report.update(errors=audit.errors, undetermined=audit.unknown, input_sha256=audit.hashes)
    code = 1 if audit.errors else 2  # No green whole-inventory result with unresolved scope.
    report['exit_code'] = code
    (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    summary = ('# P0 inventory: ' + report['status'] + '\n\n'
               + 'Explicit routes: ' + report.get('routes_status', 'NOT_RUN') + '\n\n'
               + f'Errors: {len(audit.errors)}; undetermined scope items: {len(audit.unknown)}.\n\n'
               + 'This is static inventory evidence, not P0 acceptance. See report.json.\n')
    (output / 'summary.md').write_text(summary)
    if os.getenv('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(summary)
    print(summary)
    return code


if __name__ == '__main__':
    sys.exit(main())
