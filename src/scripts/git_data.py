import subprocess

def get_last_commit_date(file_path):
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

if __name__ == '__main__':
    print(get_last_commit_date('./CONTRIBUTING.md'))

