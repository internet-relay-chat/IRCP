#!/usr/bin/env python
# ircp logs parser - developed by acidvegas in python (https://git.acid.vegas/ircp)

import json
import os
import sys

def parse(data, raw=True):
	if not raw:
		data = ' '.join(line.split()[3:])
		if data[:1] == ':':
			data = data[1:]
	print(data)
	return data

# Main
if len(sys.argv) >= 2:
	option  = sys.argv[1]
	raw    = True
	if len(sys.argv) == 3:
		if sys.argv[2] == 'clean':
			raw = False
	logs  = os.listdir('logs')
	found = list()
	for log in logs:
		with open('logs/'+log) as logfile:
			data = json.loads(logfile.read())
			if option in data:
				data = data[option]
				if type(data) == str:
					found.append(parse(data, raw))
				elif type(data) == list:
					for item in data:
						found.append(parse(item, raw))
	if found:
		print(f'\nfound {len(found)} results in {len(logs)} logs')
else:
	print('usage: python parser.py <field> [clean]\n')
	print('       <field> may be any item in the snapshots (001, NOTICE, 464, etc)')
	print('       [clean] may be optionally used to display a cleaner output')