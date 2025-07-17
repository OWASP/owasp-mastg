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
]

# Regex patterns for different file types
ID_PATTERNS = {
    "best-practices": r"MASTG-BEST-(\d{4})",
    "demos": r"MASTG-DEMO-(\d{4})",
    "techniques": r"MASTG-TECH-(\d{4})",
    "tools": r"MASTG-TOOL-(\d{4})",
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
    return f"{prefix}-{next_id:04d}", next_id

def main():
    # Dictionary to store all existing IDs by prefix
    existing_ids_by_prefix = defaultdict(list)
    # Dictionary to map existing IDs to their file paths
    id_to_path = {}
    # List to store duplicate files info
    duplicates = []
    has_duplicates = False
    # Dictionary to keep track of next ID to use for each prefix
    next_id_numbers = {}

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

    # Debug: Print the files we're checking
    print("Files to check in PR:")
    for file in new_files_in_pr:
        print(f"- {file}")

    # First pass: collect all existing IDs (excluding the new files in PR)
    for folder in FOLDERS_TO_CHECK:
        # Get the prefix for this folder
        prefix_match = None
        for key in ID_PATTERNS:
            # Check if key is in folder name or folder is in key
            if key in folder:
                prefix_match = key
                break
        
        if not prefix_match:
            print(f"Warning: No pattern match found for folder: {folder}")
            continue  # Skip folders without a defined pattern

        pattern = ID_PATTERNS[prefix_match]
        print(f"Scanning folder: {folder} with pattern: {pattern}")
        
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
                
                id_prefix = "-".join(file_id.split("-")[:2])
                
                # Record the ID and its associated path
                existing_ids_by_prefix[id_prefix].append(id_number)
                id_to_path[file_id] = filepath
                print(f"Found existing ID: {file_id} in {filepath}")

    # Initialize next ID numbers for each prefix based on existing highest values
    for prefix, ids in existing_ids_by_prefix.items():
        if ids:
            next_id_numbers[prefix] = max(int(id_str) for id_str in ids) + 1
        else:
            next_id_numbers[prefix] = 1

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
            print(f"Warning: No pattern match found for file: {filepath}")
            continue  # Skip files without a matching pattern
            
        pattern = ID_PATTERNS[prefix_match]
        filename = os.path.basename(filepath)
        
        print(f"Checking file: {filepath} with pattern: {pattern}")
        
        # Try to find the ID in the filename
        match = re.search(pattern, filename)
        if not match:
            print(f"No ID pattern match in filename: {filename}")
            continue  # Skip files without an ID in the filename
            
        file_id = match.group(0)  # Full match like MASTG-BEST-0001
        id_number = match.group(1)  # Just the number part (0001)
        
        id_prefix = "-".join(file_id.split("-")[:2])
        
        print(f"Found ID: {file_id} with prefix: {id_prefix} in new file: {filepath}")
        
        # Check if this ID already exists
        if file_id in id_to_path:
            has_duplicates = True
            
            # Get the next available ID based on our tracking
            next_id_num = next_id_numbers.get(id_prefix, 1)
            suggested_id = f"{id_prefix}-{next_id_num:04d}"
            
            # Increment the next ID number for this prefix
            next_id_numbers[id_prefix] = next_id_num + 1
            
            duplicates.append({
                "file_path": filepath,
                "file_id": file_id,
                "existing_path": id_to_path[file_id],
                "suggested_id": suggested_id
            })
            print(f"Duplicate found: {file_id} already exists in {id_to_path[file_id]}")
        else:
            # Record this ID so if there are multiple new files with the same ID,
            # we'll catch those duplicates too
            id_to_path[file_id] = filepath
            existing_ids_by_prefix[id_prefix].append(id_number)
            print(f"New unique ID: {file_id} in {filepath}")

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