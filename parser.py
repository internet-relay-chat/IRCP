#!/usr/bin/env python
# ircp logs parser - developed by acidvegas in python (https://git.acid.vegas/ircp)

import json
import os
import sys

def parse(line, raw): # TODO: finish adding custom outputs for certain fields
	if not raw:
		args    = line.split()
		numeric = args[1]
		data    = ' '.join(args[3:])
		if data[:1] == ':':
			data = data[1:]
		if numeric == '001' and len(args) >= 7 and data.lower().startswith('welcome to the '):
			return args[6]
		elif numeric == '002' and len(line.split('running version ')) == 2:
			return line.split('running version ')[1]
		elif numeric == '003':
			check = [item for item in ('This server was cobbled together ','This server was created ','This server has been started ','This server was last re(started) on ','This server was last (re)started on ') if data.startswith(item)]
			if check:
				return data.replace(check[0],'')
		elif numeric == '004' and len(args) >= 5:
			return args[4]
		elif numeric == '005':
			return data.split(' :')[0]
		elif numeric == '006':
			while data[:1] in ('-','|',' ','`'):
				data = data[1:]
			return data.split()[0]
	return line if raw else data

def stats(lines):


# Main
if len(sys.argv) >= 2:
	check  = sys.argv[1]
	raw    = True
	stats  = False
	if len(sys.argv) == 3:
		if sys.argv[2] == 'clean':
			raw = False
		elif sys.argv == 'stats':
			stats = True
	logs  = os.listdir('logs')
	found = list()
	for log in logs:
		with open('logs/'+log) as logfile:
			data = json.loads(logfile.read())
			if check in data:
				data = data[check]
				if type(data) == str:
					print(parse(data, raw))
					found.append(parse(data, raw))
				elif type(data) == list:
					for item in data:
						print(parse(item, raw))
						found.append(parse(item, raw))
	if stats:
		database = dict()
		for item in found:
			if item not in database:
				database[item] = 1
			else:
				database[item] +=1
	print(database)
	print(f'\nFound {len(found)} results in {len(logs)} logs')
else:
	print('usage: python parser.py <field> [clean]\n')
	print('       <field> may be any item in the snapshots (001, NOTICE, 464, etc)')
	print('       [clean] may be optionally used to display a cleaner output')