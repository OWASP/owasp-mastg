# Use the latest Python image
FROM python:3-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y git jq curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY src/scripts/requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

# Clone the OWASP MASVS and MASWE as required by the website build
RUN git clone --depth 1 https://github.com/OWASP/masvs.git /workspaces/masvs
RUN git clone --depth 1 https://github.com/OWASP/maswe.git /workspaces/maswe

# Set the working directory this way to be compatible with devcontainers and also run independently
WORKDIR /workspaces/mastg

# Expose port 8000
EXPOSE 8000

# Start the container with a shell
# Specific -w (watch) folders are added as otherwise MkDocs will not watch for changes in these directories as they are outside of the docs root
CMD ["sh", "-c", "mkdocs serve -a 0.0.0.0:8000 -w ./techniques/ -w ./tools/ -w ./apps/ -w ./demos/ -w ./rules/ -w ./utils/ -w ./best-practices/ -w ./tests/"]
