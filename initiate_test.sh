#!/bin/bash


if [ $# -ne 1 ]; then
    echo "Usage: $0 <file_or_directory>"
    exit 1
fi

if [ ! -e "$1" ]; then
    echo "Error: '$1' does not exist."
    exit 1
fi

INPUT="$(realpath "$1")"


if [ -f "$INPUT" ]; then
    echo "Input is a FILE: $INPUT"
    python3 scripts/vuln_scanner.py --path "$INPUT" --output output.json

elif [ -d "$INPUT" ]; then
    echo "Input is a DIRECTORY: $INPUT"
    python3 scripts/vuln_scanner.py --path "$INPUT" --output output.json

else
    echo "Error: '$INPUT' is neither a valid file nor a directory."
    exit 1
fi


if [ ! -f "output.json" ]; then
    echo "Error: output.json was not generated."
    exit 1
fi

echo ""
echo "─── output.json ───────────────────────────"
cat output.json
echo ""
echo "────────────────────────────────────────────"


read -rp "Push changes to GitHub? [yes/no]: " ANSWER


if [[ "$ANSWER" == "yes" || "$ANSWER" == "y" ]]; then
    if [ -f "$INPUT" ]; then
        cd "$(dirname "$INPUT")" || { echo "Error: could not change to directory '$(dirname "$INPUT")'."; exit 1; }
    else
        cd "$INPUT" || { echo "Error: could not change to directory '$INPUT'."; exit 1; }
    fi


    echo "Verifying SSH connection to GitHub..."
    if ! ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
        echo "Error: SSH connection to GitHub is not configured."
        echo "Set up SSH keys (see README.md) before running this script."
        exit 1
    fi
    echo "SSH connection verified."

    if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        git init || { echo "Error: git init failed."; exit 1; }
    fi

    REMOTE_URL="$(git remote get-url origin 2>/dev/null)"

    if [ -n "$REMOTE_URL" ] && [[ "$REMOTE_URL" == https://github.com/* ]]; then
        REPO_PATH="${REMOTE_URL#https://github.com/}"
        REPO_PATH="${REPO_PATH%.git}"
        REMOTE_URL="git@github.com:${REPO_PATH}.git"
        git remote set-url origin "$REMOTE_URL"
    fi

    if [ -z "$REMOTE_URL" ]; then
        echo ""
        read -rp "Does the GitHub repo already exist? [yes/no]: " REPO_EXISTS

        if [[ "$REPO_EXISTS" == "yes" || "$REPO_EXISTS" == "y" ]]; then
            read -rp "Paste the GitHub repo URL (SSH or HTTPS): " REMOTE_URL
            if [ -z "$REMOTE_URL" ]; then
                echo "Error: repo URL cannot be empty."
                exit 1
            fi
            if [[ "$REMOTE_URL" == https://github.com/* ]]; then
                REPO_PATH="${REMOTE_URL#https://github.com/}"
                REPO_PATH="${REPO_PATH%.git}"
                REMOTE_URL="git@github.com:${REPO_PATH}.git"
            fi
            git remote add origin "$REMOTE_URL" 2>/dev/null || git remote set-url origin "$REMOTE_URL"

        else
            read -rsp "GitHub personal access token (used only to create the repo): " GH_TOKEN
            echo ""
            if [ -z "$GH_TOKEN" ]; then
                echo "Error: token cannot be empty."
                exit 1
            fi

            read -rp "Name for the new repo: " REPO_NAME
            if [ -z "$REPO_NAME" ]; then
                echo "Error: repo name cannot be empty."
                unset GH_TOKEN
                exit 1
            fi

            read -rp "Make it private? [yes/no]: " REPO_PRIVATE
            if [[ "$REPO_PRIVATE" == "yes" || "$REPO_PRIVATE" == "y" ]]; then
                PRIVATE_FLAG="true"
            else
                PRIVATE_FLAG="false"
            fi

            echo "Creating repo '$REPO_NAME' on GitHub..."
            CREATE_RESPONSE="$(curl -s -X POST "https://api.github.com/user/repos" \
                -H "Authorization: token $GH_TOKEN" \
                -H "Accept: application/vnd.github+json" \
                -d "{\"name\":\"$REPO_NAME\",\"private\":$PRIVATE_FLAG}")"

            unset GH_TOKEN

            REMOTE_URL="$(echo "$CREATE_RESPONSE" | grep -o '"ssh_url": *"[^"]*"' | head -1 | sed -E 's#.*"ssh_url": *"([^"]*)".*#\1#')"

            if [ -z "$REMOTE_URL" ]; then
                ERR_MSG="$(echo "$CREATE_RESPONSE" | grep -o '"message": *"[^"]*"' | head -1 | sed -E 's#.*"message": *"([^"]*)".*#\1#')"
                echo "Error: repo creation failed. ${ERR_MSG:-unknown error}"
                exit 1
            fi

            echo "Repo created: $REMOTE_URL"
            git remote add origin "$REMOTE_URL" 2>/dev/null || git remote set-url origin "$REMOTE_URL"
        fi
    fi

    read -rp "Enter a commit message (press Enter for default): " COMMIT_MSG
    COMMIT_MSG="${COMMIT_MSG:-Auto-commit: processed $INPUT}"

    git add .
    if git diff --cached --quiet; then
        echo "Nothing to commit — working tree is clean relative to the index."
        exit 0
    fi
    git commit -m "$COMMIT_MSG"

    echo "Pushing to GitHub..."
    CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
    if git push -u origin "$CURRENT_BRANCH"; then
        echo "Done! Changes pushed successfully."
    else
        echo "Error: push failed."
        exit 1
    fi
else
    echo "Skipping GitHub push."
fi
