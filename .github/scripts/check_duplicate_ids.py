#!/usr/bin/env python3

import os
import re
import json
import glob
from collections import defaultdict

# Folders to check
FOLDERS_TO_CHECK = [
    "apps",
    "best-practices",
    "demos",
    "tests-beta",
    "tools",
    "techniques",
    "weaknesses"
]

# Regex patterns for different file types
ID_PATTERNS = {
    "best-practices": r"MASTG-BEST-(\d{4})",
    "demos": r"MASTG-DEMO-(\d{4})",
    "techniques": r"MASTG-TECH-(\d{4})",
    "tools": r"MASTG-TOOL-(\d{4})",
    "weaknesses": r"MASTG-WEAK-(\d{4})",
    "apps": r"MASTG-APP-(\d{4})",
    "tests-beta": r"MASTG-TEST-(\d{4})"
}

def find_next_available_id(prefix, existing_ids):
    """Find the next available ID for a given prefix"""
    if not existing_ids:
        return f"{prefix}-0001"
    
    # Convert to integers and find the highest
    highest = max(int(id_str) for id_str in existing_ids)
    next_id = highest + 1
    return f"{prefix}-{next_id:04d}"

def main():
    # Dictionary to store all existing IDs by prefix
    existing_ids_by_prefix = defaultdict(list)
    # Dictionary to map existing IDs to their file paths
    id_to_path = {}
    # List to store duplicate files info
    duplicates = []
    has_duplicates = False

    # Load list of new files in PR
    new_files_in_pr = []
    if os.path.exists("new_files_in_pr.txt"):
        with open("new_files_in_pr.txt", "r") as f:
            new_files_in_pr = [line.strip() for line in f.readlines()]
    
    # If no new files, exit early
    if not new_files_in_pr:
        print("No new files found in PR.")
        # Set output for GitHub Actions using the new environment file approach
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write("has_duplicates=false\n")
        return

    # First pass: collect all existing IDs (excluding the new files in PR)
    for folder in FOLDERS_TO_CHECK:
        # Get the prefix for this folder
        prefix_match = None
        for key in ID_PATTERNS:
            if key in folder or folder in key:
                prefix_match = key
                break
        
        if not prefix_match:
            continue  # Skip folders without a defined pattern

        pattern = ID_PATTERNS[prefix_match]
        
        # Search for all markdown files in the folder and subfolders
        for filepath in glob.glob(f"{folder}/**/*.md", recursive=True):
            # Skip index.md files and new files in PR
            if os.path.basename(filepath) == "index.md" or filepath in new_files_in_pr:
                continue
            
            # Extract the filename
            filename = os.path.basename(filepath)
            
            # Try to find the ID in the filename
            match = re.search(pattern, filename)
            if match:
                file_id = match.group(0)  # Full match like MASTG-BEST-0001
                id_number = match.group(1)  # Just the number part (0001)
                
                # Record the ID and its associated path
                existing_ids_by_prefix[file_id.split("-")[0] + "-" + file_id.split("-")[1]].append(id_number)
                id_to_path[file_id] = filepath

    # Second pass: check new files against existing IDs
    for filepath in new_files_in_pr:
        # Skip non-markdown files
        if not filepath.endswith('.md'):
            continue
            
        # Skip index.md files
        if os.path.basename(filepath) == "index.md":
            continue
            
        # Determine which prefix pattern this file uses
        prefix_match = None
        for key in ID_PATTERNS:
            if key in filepath:
                prefix_match = key
                break
                
        if not prefix_match:
            continue  # Skip files without a matching pattern
            
        pattern = ID_PATTERNS[prefix_match]
        filename = os.path.basename(filepath)
        
        # Try to find the ID in the filename
        match = re.search(pattern, filename)
        if not match:
            continue  # Skip files without an ID in the filename
            
        file_id = match.group(0)  # Full match like MASTG-BEST-0001
        id_number = match.group(1)  # Just the number part (0001)
        
        # Check if this ID already exists
        if file_id in id_to_path:
            has_duplicates = True
            # Determine which prefix pattern this file uses
            id_prefix = file_id.split("-")[0] + "-" + file_id.split("-")[1]
            
            # Add this ID to the list for calculating next available ID
            existing_ids_by_prefix[id_prefix].append(id_number)
            
            # Get the next available ID
            suggested_id = find_next_available_id(id_prefix, existing_ids_by_prefix[id_prefix])
            
            duplicates.append({
                "file_path": filepath,
                "file_id": file_id,
                "existing_path": id_to_path[file_id],
                "suggested_id": suggested_id
            })
        else:
            # Record this ID so if there are multiple new files with the same ID,
            # we'll catch those duplicates too
            id_to_path[file_id] = filepath
            id_prefix = file_id.split("-")[0] + "-" + file_id.split("-")[1]
            existing_ids_by_prefix[id_prefix].append(id_number)

    # Set output for GitHub Actions using the new environment file approach
    github_output = os.environ.get('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as f:
            f.write(f"has_duplicates={'true' if has_duplicates else 'false'}\n")
    
    # Save duplicates info to a file for the next step if any found
    if has_duplicates:
        with open("duplicate_files.json", "w") as f:
            json.dump(duplicates, f)
        
        # Print information about the duplicates
        print(f"Found {len(duplicates)} duplicate file IDs in new files:")
        for dup in duplicates:
            print(f"  - {dup['file_path']} duplicates {dup['existing_path']}")
            print(f"    Suggested ID: {dup['suggested_id']}")
    else:
        print("No duplicate file IDs found in new files.")

if __name__ == "__main__":
    main()