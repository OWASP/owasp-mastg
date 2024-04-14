#!/bin/bash

# Define the project and rules directories
PROJECT_DIR="./example"
RULES_DIR="./rules"

# Running Semgrep with all the rules against the project directory
semgrep --config=$RULES_DIR/backup-unencrypted-rule.yaml \
        --config=$RULES_DIR/sharedpreferences_sensitive_data.yaml \
        --config=$RULES_DIR/cloud-backup-sensitive-data-rule.yaml \
        --config=$RULES_DIR/external_storage_sensitive_data.yaml \
        --config=$RULES_DIR/insecure-device-conditions.yaml \
        --config=$RULES_DIR/missing_encryption_api_usage.yaml \
        $PROJECT_DIR

echo "Semgrep analysis completed."
