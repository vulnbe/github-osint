# GitHub OSINT tool

This tool uses GitHub API to get email addresses from commit log of user/organisation repositories

It can be operated with/without GitHub API token.

## How to:

```
git clone https://github.com/vulnbe/github-osint.git
cd github-osint
pip install -r requirements.txt
python github-osint.py --owner vulnbe
```

If you reach the API request limit, then use [token](https://github.com/settings/tokens).
