from datetime import datetime
import json
import os
import requests
import subprocess

def get_last_commit_date(file_path):
    try:
        # get the last commit date as "September 12, 2022"
        GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

        if GITHUB_TOKEN is None:
            print('Github token not found')
            return None
        
        headers = {
            'X-GitHub-Api-Version': '2022-11-28',
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {GITHUB_TOKEN}'
        }

        url = f'https://api.github.com/repos/OWASP/owasp-mastg/commits?path={file_path}'
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            response.raise_for_status()

        data = response.json()

        if 'message' in data:
            raise Exception(data['message'])
        if data and 'commit' in data[0]:
            commit_date_in_utc = data[0]['commit']['committer']['date']
            fmt_date = datetime.strptime(commit_date_in_utc, '%Y-%m-%dT%H:%M:%SZ').strftime('%B %d, %Y')
            return fmt_date
        
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

if __name__ == '__main__':
    print(get_last_commit_date('./CONTRIBUTING.md'))

