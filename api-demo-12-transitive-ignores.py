import json
import argparse

import SnykAPI


def print_json(json_obj):
    print(json.dumps(json_obj, indent=4))


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='The Snyk Organisation Id')

    args = parser.parse_args()

    if args.orgId is None:
        parser.error('You must specify --orgId')

    return args


args = parse_command_line_args()
org_id = args.orgId

json_res_projects = SnykAPI.snyk_projects_projects(org_id)

# Create a list containing project ids
projects = [proj['id'] for proj in json_res_projects['projects']]

# For each project
for proj in projects:
    json_res_project_ignores = SnykAPI.snyk_projects_project_issues(
        org_id, proj, ignored=True)
    # For each vulnerability in the project
    for vulnerability in json_res_project_ignores['issues']['vulnerabilities']:
        print("Processing vuln with id [%s] from project [%s]" % (vulnerability['id'], proj))
        for proj_id in projects:
            if proj_id != proj:
                print("Ignoring vuln: [%s] for project [%s]" %
                    (vulnerability['id'], proj_id))
                response = SnykAPI.snyk_projects_add_ignore_by_issue(
                    org_id, proj_id, vulnerability['id'], vulnerability['ignored'][0]['reasonType'], vulnerability['ignored'][0]['expires'])
                response.raise_for_status()
