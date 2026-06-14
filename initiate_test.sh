#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <file_or_directory>"
    exit 1
fi

INPUT="$(realpath "$1")"

# Step 2: Check if argument is a file or directory
if [ -f "$INPUT" ]; then
    echo "Input is a FILE: $INPUT"
    python3 scripts/vuln_scanner.py "$INPUT" --output report.json

elif [ -d "$INPUT" ]; then
    echo "Input is a DIRECTORY: $INPUT"
    python3 scripts/vuln_scanner.py "$INPUT" --output report.json

else
    echo "Error: '$INPUT' is not valid!"
    exit 1
fi

# Step 3: Print the generated output.json
if [ ! -f "output.json" ]; then
    echo "Error: output.json was not generated."
    exit 1
fi

cat output.json

read -rp "Would you like to push to GitHub? [yes/no]: " ANSWER

# Step 5: Push to GitHub if "yes"
if [[ "$ANSWER" == "yes" || "$ANSWER" == "y" ]]; then
    # Verify SSH connection to GitHub before pushing
    echo "Verifying SSH connection to GitHub..."
    if ! ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
        echo "Error: SSH connection to GitHub is not configured."
        echo "Please follow the SSH setup steps in README.md before running this script."
        exit 1
    fi
    echo "SSH connection verified."

    read -rp "Enter a commit message (press Enter for default): " COMMIT_MSG
    COMMIT_MSG="${COMMIT_MSG:-"Auto-commit: processed $INPUT"}"
    echo "Pushing to GitHub..."
    if [ -f "$INPUT" ]; then
        cd "$(dirname "$INPUT")" || { echo "Error: could not change to directory '$(dirname "$INPUT")'."; exit 1; }
    else
        cd "$INPUT" || { echo "Error: could not change to directory '$INPUT'."; exit 1; }
    fi
    git add .
    git commit -m "Auto-commit: processed $INPUT"
    git push
    echo "Done! Changes pushed successfully. Don't forget to Git Better ;)"
else
    echo "Skipping GitHub push."
fi
