# SIEM – Auth Log Analyzer

A small Python tool that parses Linux authentication logs (`auth.log`) to detect failed SSH login attempts using regular expressions.

## Features
- Finds "Failed password" entries in the log
- Extracts the targeted username and source IP with regex groups
- Counts failed attempts

## Usage

python SIEM.py

Place an auth log named sample_auth.txt in the same folder before running.


## What I practiced
- Regular expressions (`re.search`, groups, named groups)
- Reading and parsing log files in Python
- Basic security log analysis