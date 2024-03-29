#!/usr/bin/env python
# ircp logs parser - developed by acidvegas in python (https://git.acid.vegas/ircp)

import json
import os
import sys

def parse(option, data, raw=True):
	if not raw:
		data = ' '.join(data.split()[3:])
		if data[:1] == ':':
			data = data[1:]
	if type(data) == bool:
		data = str(data)
	print(data.replace(option, f'\033[31m{option}\033[0m'))
	return data

# Main
if len(sys.argv) >= 2:
	option  = sys.argv[1]
	raw    = True
	search = False
	if len(sys.argv) == 3:
		if sys.argv[2] == 'clean':
			raw = False
		elif sys.argv[2] == 'search':
			search = True
	logs  = os.listdir('logs')
	found = list()
	for log in logs:
		with open('logs/'+log) as logfile:
			try:
				data = json.loads(logfile.read())
			except:
				print('error: failed to load ' + log)
				break
			if option in data:
				data = data[option]
				if type(data) == str:
					found.append(parse(option, data, raw))
				elif type(data) == list:
					for item in data:
						found.append(parse(option, item, raw))
			elif search:
				for item in data:
					_data = data[item]
					if type(_data) == str and option in _data:
						found.append(parse(option, item, raw))
					elif type(_data) == list:
						for _item in _data:
							if option in _item:
								found.append(parse(option, _item, raw))
	if found:
		print(f'\nfound {len(found)} results in {len(logs)} logs')
else:
	print('usage: python parser.py <field> [clean]\n')
	print('       <field> may be any item in the snapshots (001, NOTICE, 464, etc) or a string to search')
	print('       [clean] may be optionally used to display a cleaner output')
