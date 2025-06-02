# How to Run the OWASP MAS Website Locally

This guide will help you set up and run the OWASP MAS website locally on your machine. Follow the steps below to get started.

> **TLDR for advanced users:**
>
> - Setup a virtual environment
> - Install dependencies from `src/scripts/requirements.txt`
> - Run the website using `./run_web.sh`

## Prerequisites

Before running the website, ensure you have the following installed on your system:

- Python 3.8 or higher
- pip (Python package manager)
- Git
- Visual Studio Code (vscode)
- Gnu sed (gsed; e.g. `brew install gnu-sed` on macOS)

Add an alias for `gsed` (e.g. in your .zshrc file):

```bash
alias sed='gsed'
```

[Create a personal access token](https://github.com/settings/personal-access-tokens) on Github and export this token as environment variable (e.g. in your .zshrc file):

```bash
export GITHUB_TOKEN=<TOKEN>
```

## Step 1: Clone the OWASP MASVS & OWASP MASTG Repositories

Run the following commands in your terminal:

```bash
git clone https://github.com/OWASP/owasp-masvs.git
git clone https://github.com/OWASP/owasp-mastg.git
```

**Note:** We'll just work with the `OWASP/owasp-mastg` repo, but the `OWASP/owasp-masvs` is required for the website to run.

## Step 2: Open the OWASP MASTG Repository in vscode

Run the following commands in your terminal:

```bash
cd owasp-mastg
code .
```

## Step 3: Install Python Dependencies

It is highly recommended to use a virtual environment (venv) to manage dependencies and avoid conflicts with other Python projects. Follow these steps to set up a virtual environment and install the required dependencies.

Use vscode's [`Command Palette`](https://code.visualstudio.com/docs/getstarted/userinterface#_command-palette) (Press `⌘+Shift+P` on macOS or `Ctrl+Shift+P` on Windows/Linux)

1. Create a venv:
    - Press `⌘+Shift+P` -> `Python: Create Environment`
    - Select `"Quick Create"`
2. Select the venv as the Python interpreter:
    - Press `⌘+Shift+P` -> `Python: Select Interpreter`
    - Choose the venv you just created.
3. Install the dependencies
   - Press `⌘ + j` to open the terminal
   - Run `pip install -r src/scripts/requirements.txt`

## Step 4: Run the Website

Run the following command in the terminal:

```bash
./run_web.sh
```

Access the website at [http://localhost:8000](http://localhost:8000).

## Step 5: Debugging the Website

To debug the website:

- Go to `Run and Debug` in vscode (or press `⌘+Shift+D` on macOS)
- Select `Python: MkDocs Serve`
- Click the green play button to start debugging
- Set breakpoints in the code as needed
