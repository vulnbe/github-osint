#!/usr/bin/env python3
"""
https://vuln.be/github-osint.html
https://github.com/vulnbe/github-osint
"""

import sys
import requests
import json
import logging
import re
import argparse

from multiprocessing.dummy import Pool

threads_num = 4
logformat = '%(asctime)s %(message)s'

class Identity(object):
  name = None
  email = None
  def __init__(self, name, email):
    self.name = name
    self.email = email
  def __key(self):
    return (self.name, self.email)
  def __eq__(self, x):
    return self.__key() == x.__key()
  def __hash__(self):
    return hash(self.__key())

class Supplicant(object):
  _headers = {'User-Agent':'Mozilla/5.0 (github-osint https://github.com/vulnbe/github-osint)'}
  def __init__(self, api_token):
    if api_token:
      self._headers['Authorization'] = 'token {}'.format(api_token)
  def get_content(self, url):
    logging.debug('Fetching file {}'.format(url))
    response = requests.get(url, headers=self._headers)
    if response.ok:
      try:
        return response.json() + self.get_content(response.links['next']['url'])
      except:
        return response.json()
    else:
      return []

def print_banner():
  print(' _______ __ __   _______         __           _______ _______ _______ _______ _______ ')
  print('|     __|__|  |_|   |   |.--.--.|  |--.______|       |     __|_     _|    |  |_     _|')
  print('|    |  |  |   _|       ||  |  ||  _  |______|   -   |__     |_|   |_|       | |   |  ')
  print('|_______|__|____|___|___||_____||_____|      |_______|_______|_______|__|____| |___|  ')
  print('')

def main(args):
  if args.verbose:
    logging.basicConfig(format=logformat, level=logging.DEBUG)
  else:
    logging.basicConfig(format=logformat, level=logging.INFO)

  account_apis = ['https://api.github.com/orgs/{}/repos', 'https://api.github.com/users/{}/repos']
  supplicant = Supplicant(args.token)
  repos = None
  
  logging.info('Scanning account {}...'.format(args.owner))
  for url in account_apis:
    repos = supplicant.get_content(url.format(args.owner))
    if len(repos):
      break
  
  repos_commits = None
  if repos:
    logging.info('Found {} repositories'.format(len(repos)))
    repos_filtered = list(map(lambda x: x['commits_url'].replace('{/sha}',''), 
      filter(lambda x: x['fork'] == False or x['fork'] == args.forks, repos)))
    
    logging.info('Fetching commits from {} repositories ({} skipped)...'.format(len(repos_filtered),
      len(repos)-len(repos_filtered)))
    
    pool = Pool(args.threads)
    repos_commits = pool.map(supplicant.get_content, repos_filtered)
    pool.close()
    pool.join()
  else:
    logging.info('Repositories not found')
    sys.exit(0)
  
  repos_identities = {}
  if repos_commits:
    for commits in repos_commits:
      identities = set()
      for commit in commits:
        for field in ['author', 'committer']:
          if commit['commit'][field]:
            identity = Identity(commit['commit'][field]['name'], 
                                commit['commit'][field]['email'])
            identities.add(identity)
      repos_identities[re.sub(r'/commits/.*', '', commits[0]['url'])] = identities

  for repo_name, identities in repos_identities.items():
    print(repo_name)
    while len(identities) > 0:
      identity = identities.pop()
      print('\t{} <{}>'.format(identity.name, identity.email))

if __name__ == '__main__':
  print_banner()
  parser = argparse.ArgumentParser(description=
    'Small intelligence tool for retriving info about github organisation\'s or user\'s commit log')
  parser.add_argument('--owner', required=True, help='user or organisation name, eg. vulnbe')
  parser.add_argument('--forks', action='store_true', help='include forks')
  parser.add_argument('--verbose', action='store_true', help='show debug info')
  parser.add_argument('--token', required=False, help='GitHub API token (for better rate limits)')
  parser.add_argument('--threads', required=False, help='thereads to fetch data', type=int, default=threads_num)
  args = parser.parse_args()
  main(args)
