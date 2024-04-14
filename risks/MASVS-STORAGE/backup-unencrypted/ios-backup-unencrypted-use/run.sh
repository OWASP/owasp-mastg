#!/bin/bash

# Define paths
RULES_DIR="./rules"
EXAMPLE_DIR="./examples"

# Placeholder for running Semgrep (or guiding manual review)
echo "Running static analysis for iOS backup security..."
semgrep --config=$RULES_DIR/detect_sensitive_data_storage.yaml $EXAMPLE_DIR

echo "Review the guidelines in the Rules directory for manual analysis steps."
