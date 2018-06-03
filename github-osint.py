#!/usr/bin/env python
"""
https://vuln.be/github-osint.html
https://github.com/vulnbe/github-osint
"""

import sys
import requests
import json
from multiprocessing.dummy import Pool

threadsNum = 4

class Response(object):
    url = None
    content = None
    def __init__(self, url, content):
        self.url = url
        self.content = content

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
    def __init__(self, apiToken):
        if apiToken:
            self._headers['Authorization'] = 'token %s' % apiToken
    def getContent(self, url):
        response = requests.get(url, headers=self._headers)
        if response.ok:
            return Response(url, json.loads(str(response.content)))
        else:
            return Response(url, None)

def printBanner():
    print(' _______ __ __   _______         __           _______ _______ _______ _______ _______ ')
    print('|     __|__|  |_|   |   |.--.--.|  |--.______|       |     __|_     _|    |  |_     _|')
    print('|    |  |  |   _|       ||  |  ||  _  |______|   -   |__     |_|   |_|       | |   |  ')
    print('|_______|__|____|___|___||_____||_____|      |_______|_______|_______|__|____| |___|  ')
    print('')

def printHelp(args):
    print('Small intelligence tool for retriving info about github organisation\'s or user\'s commit log')
    print('')
    print('Usage:')
    print('\t%s org/user [github_API_token]' % args[0])
    print('\tYou can provide github API token for better rate limits')
    print('Example:')
    print('\t%s hackstep 8a5934baf2cafe3ddeadbeef31737' % args[0])

def main(args):
    owner = args[0]
    apiToken = None
    if len(args) == 2:
        apiToken = args[1]
    accountAPI = ['https://api.github.com/orgs/%s/repos', 'https://api.github.com/users/%s/repos']
    supplicant = Supplicant(apiToken)
    repos = None
    
    for url in accountAPI:
        response = supplicant.getContent(url % owner)
        if response.content:
            repos = response.content
            break
    
    commitsArray = None
    if repos:
        pool = Pool(threadsNum)
        commitsArray = pool.map(supplicant.getContent, [ repo['commits_url'].replace('{/sha}','') for repo in repos])
        pool.close()
        pool.join()
    else:
        print('Repositories not found')
        sys.exit(1)
    
    repos = {}
    if commitsArray:
        print('Found %s repositories:' % len(commitsArray))
        for commits in commitsArray:
            if commits.content:
                identities = set()
                for commit in commits.content:
                    for field in ['author', 'committer']:
                        if commit['commit'][field]:
                            identity = Identity(commit['commit'][field]['name'], commit['commit'][field]['email'])
                            identities.add(identity)
                repos[commits.url.replace('/commits','')] = identities
            else:
                print('Error fetching commits for URL %s' % commits.url)

    for repoName, identities in repos.items():
        print('\t%s' % repoName)
        while len(identities) > 0:
            identity = identities.pop()
            print('\t\t%s <%s>' % (identity.name, identity.email))

if __name__ == '__main__':
    printBanner()
    if len(sys.argv) < 2 or sys.argv[1] in ['-h','-help','--help']:
        printHelp(sys.argv)
    else:
        main(sys.argv[1:])
