"""Release comparison and portable CI findings, without guessing exploitability."""
import hashlib


def identity(finding):
    return hashlib.sha256((finding['rule_id'] + '|' + str(finding.get('location') or '')).encode()).hexdigest()[:24]


def compare_results(before, after):
    left_package = before['profile'].get('package_name')
    right_package = after['profile'].get('package_name')
    if not left_package or left_package != right_package:
        raise ValueError('Compare two releases with the same known package name.')
    def group(result):
        grouped = {}
        for finding in result['findings']:
            grouped.setdefault(identity(finding), []).append(finding)
        return grouped
    left, right = group(before), group(after)
    return {'package': left_package, 'before_sha256': before['profile']['sha256'], 'after_sha256': after['profile']['sha256'],
            'introduced': [finding for key in right.keys() - left.keys() for finding in right[key]],
            'removed': [finding for key in left.keys() - right.keys() for finding in left[key]],
            'changed': [{'before': left[key], 'after': right[key]} for key in left.keys() & right.keys() if left[key] != right[key]],
            'permissions_added': sorted(set(after['profile']['permissions']) - set(before['profile']['permissions'])),
            'permissions_removed': sorted(set(before['profile']['permissions']) - set(after['profile']['permissions'])),
            'note': 'Removed static signals are not proof that a vulnerability was fixed; validate runtime behavior.'}


def sarif(result):
    rules = {finding['rule_id']: {'id': finding['rule_id'], 'shortDescription': {'text': finding['title']}} for finding in result['findings']}
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [{
        'tool': {'driver': {'name': 'APK Sentinel', 'rules': list(rules.values())}},
        'results': [{'ruleId': finding['rule_id'], 'level': 'error' if finding['severity'] in ('critical', 'high') else 'warning' if finding['severity'] == 'medium' else 'note',
                     'message': {'text': finding['description'] + '\nEvidence: ' + finding['evidence']},
                     'partialFingerprints': {'findingIdentity': identity(finding)},
                     'properties': {'severity': finding['severity'], 'validation': 'static signal', 'apk_sha256': result['profile']['sha256']}}
                    for finding in result['findings']]}]}
