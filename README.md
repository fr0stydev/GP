# Graduation Project

Graduation Project for Keio University Environment and Information Studies

## Objective

Create a new penetration testing tool.  

Ideally, this tool will scan for webapp's application and if a version is successfully detected it will perform a scan to check for existing exploits as well as give information on the exploit.

## Recommendation

This program works best with ParrotOS or Kali Linux  
Using other OS will require you to install SearchSploit

## Requirements

1. Nodejs <14.0.0
2. Python3
3. Searchsploit

## How to Use

1. run the app.js file in wapp-local
2. python3 main.py 

## Features

1. Scans a website for its technology stack and automatically finds existing exploits on Exploit-DB.
2. -cms flag to scan specifically for CMS without version scan
3. Pass a hostlist with -iL flag to scan multiple urls at once.
4. Creates a report file (default=output.txt)
5. Filters CVSS score lower than 3.9, include it by the -f tag

## Ideas

1. PDF Report



