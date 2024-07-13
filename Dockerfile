# Use ubuntu:latest as the base image
FROM ubuntu:latest

# Install dependencies
RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv git jq curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy requirements.txt to the container
COPY src/scripts/requirements.txt /app/src/scripts/requirements.txt

# Create a virtual environment and install Python dependencies
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --no-cache-dir -r /app/src/scripts/requirements.txt

# Copy the rest of the application code
COPY . /app

# Run initial setup scripts
RUN . venv/bin/activate && ./src/scripts/structure_mastg.sh && \
    python3 src/scripts/transform_files.py

# Set up MASVS environment and clone the repository
RUN export MASVS_VERSION=$(curl -s https://api.github.com/repos/OWASP/owasp-masvs/releases/latest | jq -r '.tag_name') && \
    echo "MASVS_VERSION=${MASVS_VERSION}" >> /app/.env && \
    git clone --depth 1 https://github.com/OWASP/owasp-masvs.git /app/owasp-masvs

# Generate MASVS YAML and populate categories
RUN . venv/bin/activate && \
    MASVS_VERSION=$(grep MASVS_VERSION /app/.env | cut -d '=' -f 2) && \
    python3 ./owasp-masvs/tools/generate_masvs_yaml.py -v ${MASVS_VERSION} -i ./owasp-masvs/Document -c ./owasp-masvs/controls && \
    python3 ./owasp-masvs/tools/populate_masvs_categories_md.py -d ./owasp-masvs/Document -w

# Run final setup scripts
RUN . venv/bin/activate && ./src/scripts/structure_masvs.sh && \
    python3 src/scripts/write_masvs_control_md_files.py && \
    python3 src/scripts/populate_dynamic_pages.py && \
    python3 src/scripts/generate_cross_references.py

# Expose port 8000
EXPOSE 8000

# Command to run the application
CMD ["venv/bin/mkdocs", "serve", "-a", "0.0.0.0:8000"]
