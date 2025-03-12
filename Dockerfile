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

# Clone the OWASP MASVS as required by the website build
RUN git clone --depth 1 https://github.com/OWASP/owasp-masvs.git /workspaces/owasp-masvs

# Set the working directory this way to be compatible with devcontainers and also run independently
WORKDIR /workspaces/owasp-mastg

# Expose port 8000
EXPOSE 8000

# Start the container with a shell
CMD ["bash"]

# If running manually: docker run -it --rm -p 8000:8000 -v $(pwd):/workspaces/owasp-mastg mastg