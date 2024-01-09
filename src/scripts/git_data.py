from datetime import datetime
import json
import os
import requests
import subprocess

def get_last_commit_date_by_terminal_log(file_path):
    try:
        # get the last commit date as "September 12, 2022"
        command = f"git log -n 1 --date=format:'%B %d, %Y' --format=%ad -- {file_path}"
        result = subprocess.check_output(command, shell=True, universal_newlines=True)

        return result.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing Git command: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

def get_last_commit_date(file_path):
    try:
        # get the last commit date as "September 12, 2022"
        GITHUB_TOKEN = os.environ['GITHUB_TOKEN']

        if GITHUB_TOKEN is None:
            print('Github token not found')
            return get_last_commit_date_by_terminal_log(file_path)
        
        headers = {
            'X-GitHub-Api-Version': '2022-11-28',
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {GITHUB_TOKEN}'
        }

        url = f'https://api.github.com/repos/OWASP/owasp-mastg/commits?path={file_path}'
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)

        if 'message' in data:
            raise Exception(data['message'])
        elif len(data) and data[0]['commit']:
            commit_date_in_utc = data[0]['commit']['committer']['date']
            fmt_date = datetime.strptime(commit_date_in_utc, '%Y-%m-%dT%H:%M:%SZ').strftime('%B %d %Y')
            return fmt_date
        
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

if __name__ == '__main__':
    print(get_last_commit_date('./CONTRIBUTING.md'))

