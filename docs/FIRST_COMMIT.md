# First commit

At scaffold creation, the local folder was not a Git repository and the GitHub
remote had no HEAD commit. These commands assume that remote remains empty.
Do not force-push if somebody adds remote commits before you run them.

```sh
cd /Users/anshumaansharma0404gmail.com/Desktop/ML-Strugles/RIFT

git init -b main
git remote add origin https://github.com/Anshumaan657/RIFT.git

git add .
git status
git diff --cached --stat
git diff --cached

git commit -m "chore: initialize RIFT V1 project structure"
git push -u origin main
```

Review the staged diff before committing. The `.gitignore` reduces accidental
inclusion of sensitive files but is not a substitute for checking the diff.

If Git asks for your identity, set it for this repository and retry the commit:

```sh
git config user.name "YOUR NAME"
git config user.email "YOUR GITHUB EMAIL OR NOREPLY EMAIL"
```

Pushing requires GitHub authentication and permission to write to the repository.
Use your configured credential manager or GitHub CLI authentication. Do not put
tokens in the remote URL, project files, or commands saved in this repository.
