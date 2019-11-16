# GitHub OSINT tool

This tool uses GitHub API to get email addresses from commit log of user/organisation repositories

It can be operated with/without GitHub API token.

## How to:

```
git clone https://github.com/vulnbe/github-osint.git
cd github-osint
pip install -r requirements.txt
python3 github-osint.py --owner vulnbe
```

## Usage

```
github-osint.py [-h] [--forks] [--verbose]
                [--token TOKEN] [--threads THREADS]
                --owner OWNER

optional arguments:
  -h, --help         show this help message and exit
  --owner OWNER      user or organisation name, eg. vulnbe
  --forks            include forks
  --verbose          show debug info
  --token TOKEN      GitHub API token (for better rate limits)
  --threads THREADS  thereads to fetch data
```

If you reach the API request limit, then use [token](https://github.com/settings/tokens).
