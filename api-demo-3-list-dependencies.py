import json
import argparse

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id')

    parser.add_argument('--projectId', type=str,
                        help='The project ID in Snyk')

    args = parser.parse_args()

    if args.orgId is None:
        parser.error('You must specify --orgId')

    if args.projectId is None:
        parser.error('You must specify --projectId')

    return args


args = parse_command_line_args()
org_id = args.orgId
project_id = args.projectId


request_payload = {
    "projects": [
        project_id
    ]
}

# List issues in a project
lst_licenses = SnykAPI.snyk_dependencies_list_all_dependencies_by_project(org_id, project_id)

for v in lst_licenses:
    print('\n%s: %s@%s' % (v['type'], v['name'], v['version']))

    licenses = v['licenses']
    if len(licenses) > 0:
        print('  Licenses:')
        for l in licenses:
            print('   - %s | %s' % (l['license'], l['id']))

    deps_with_issues = v['dependenciesWithIssues']
    if len(deps_with_issues) > 0:
        print('  Deps with Issues:')
        for d in deps_with_issues:
            print('   - %s' % d)

    # print('  %s@%s' % (v['package'], v['version']))
    # print('  Severity: %s' % v['severity'])
