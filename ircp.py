#!/usr/bin/env python
# internet relay chat probe for https://internetrelaychat.org/ - developed by acidvegas in python (https://git.acid.vegas/ircp)

import asyncio
import copy
import json
import os
import random
import socket
import ssl
import sys
import time

class settings:
	errors   = False # Show connection errors
	nickname = 'IRCP'
	username = 'ircp'
	realname = 'internetrelaychat.org'
	ns_mail  = 'ircp@internetrelaychat.org'
	ns_pass  = 'changeme'
	vhost    = None # Bind to a specific IP address

class throttle:
	channels = 3   # Maximum number of channels to scan at once
	delay    = 120 # Delay before registering nick (if enabled) & sending /LIST
	join     = 10  # Delay between channel joins
	part     = 3   # Delay before leaving a channel
	threads  = 100 # Maximum number of threads running
	timeout  = 15  # Timeout for all sockets
	whois    = 3   # Delay between WHOIS requests
	ztimeout = 200 # Timeout for zero data from server

snapshot = {
	'server'   : None,
	'host'     : None,
	'raw'      : [], # All non-classified data is stored in here for analysis
	'NOTICE'   : None,
	'services' : False,
	'ssl'      : True,

	# server information
	'001' : None, # RPL_WELCOME
	'002' : None, # RPL_YOURHOST
	'003' : None, # RPL_CREATED
	'004' : None, # RPL_MYINFO
	'005' : None, # RPL_ISUPPORT
	'006' : None, # RPL_MAP
	'018' : None, # RPL_MAPUSERS
	'257' : None, # RPL_ADMINLOC1
	'258' : None, # RPL_ADMINLOC2
	'259' : None, # RPL_ADMINEMAIL
	'351' : None, # RPL_VERSION
	'364' : None, # RPL_LINKS
	'372' : None, # RPL_MOTD

	# statistic information (lusers)
	'250' : None, # RPL_STATSCONN
	'251' : None, # RPL_LUSERCLIENT
	'252' : None, # RPL_LUSEROP
	'254' : None, # RPL_LUSERCHANNELS
	'255' : None, # RPL_LUSERME
	'265' : None, # RPL_LOCALUSERS
	'266' : None, # RPL_GLOBALUSERS

	# channel information
	'332' : None, # RPL_TOPIC
	'353' : None, # RPL_NAMREPLY
	'322' : None, # RPL_LIST

	# user information (whois/who)
	'311' : None, # RPL_WHOISUSER
	'307' : None, # RPL_WHOISREGNICK
	'312' : None, # RPL_WHOISSERVER
	'671' : None, # RPL_WHOISSECURE
	'319' : None, # RPL_WHOISCHANNELS
	'320' : None, # RPL_WHOISSPECIAL
	'276' : None, # RPL_WHOISCERTFP
	'330' : None, # RPL_WHOISACCOUNT
	'338' : None, # RPL_WHOISACTUALLY
	'352' : None, # RPL_WHOREPLY

	# bad channel numerics
	'470' : None, # ERR_LINKCHANNEL
	'471' : None, # ERR_CHANNELISFULL
	'473' : None, # ERR_INVITEONLYCHAN
	'474' : None, # ERR_BANNEDFROMCHAN
	'475' : None, # ERR_BADCHANNELKEY
	'477' : None, # ERR_NEEDREGGEDNICK
	'489' : None, # ERR_SECUREONLYCHAN
	'519' : None, # ERR_TOOMANYUSERS
	'520' : None, # ERR_OPERONLY

	# bad server numerics
	'464' :	None, # ERR_PASSWDMISMATCH
	'465' :	None, # ERR_YOUREBANNEDCREEP
	'466' :	None, # ERR_YOUWILLBEBANNED
	'421' : None  # ERR_UNKNOWNCOMMAND
}

def debug(data):
	print('{0} | [~] - {1}'.format(time.strftime('%I:%M:%S'), data))

def error(data, reason=None):
	if settings.errors:
		print('{0} | [!] - {1} ({2})'.format(time.strftime('%I:%M:%S'), data, str(reason))) if reason else print('{0} | [!] - {1}'.format(time.strftime('%I:%M:%S'), data))

def rndnick():
	prefix = random.choice(['st','sn','cr','pl','pr','fr','fl','qu','br','gr','sh','sk','tr','kl','wr','bl']+list('bcdfgklmnprstvwz'))
	midfix = random.choice(('aeiou'))+random.choice(('aeiou'))+random.choice(('bcdfgklmnprstvwz'))
	suffix = random.choice(['ed','est','er','le','ly','y','ies','iest','ian','ion','est','ing','led','inger']+list('abcdfgklmnprstvwz'))
	return prefix+midfix+suffix

def ssl_ctx():
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	return ctx

class probe:
	def __init__(self, server, semaphore):
		self.server    = server
		self.semaphore = semaphore
		self.snapshot  = copy.deepcopy(snapshot) # <--- GET FUCKED PYTHON
		self.channels  = {'all':list(), 'current':list()}
		self.cchannels = dict()
		self.nicks     = {'all':list(),   'check':list()}
		self.loops     = {'init':None,'chan':None,'nick':None}
		self.reader    = None
		self.writer    = None

	async def run(self):
		async with self.semaphore:
			try:
				await self.connect()
			except Exception as ex:
				error(self.server.ljust(18) + ' | failed to connect using SSL/TLS', ex)
				try:
					await self.connect(True)
				except Exception as ex:
					error(self.server.ljust(18) + ' | failed to connect', ex)

	async def raw(self, data):
		self.writer.write(data[:510].encode('utf-8') + b'\r\n')
		await self.writer.drain()

	async def connect(self, fallback=False):
		options = {
			'host'       : self.server,
			'port'       : 6667 if fallback else 6697,
			'limit'      : 1024,
			'ssl'        : None if fallback else ssl_ctx(),
			'family'     : 2, # 2 = IPv4 | 10 = IPv6 (TODO: Check for IPv6 using server DNS)
			'local_addr' : settings.vhost
		}
		identity = {
			'nick': settings.nickname if settings.nickname else rndnick(),
			'user': settings.username if settings.username else rndnick(),
			'real': settings.realname if settings.realname else rndnick()
		}
		self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(**options), throttle.timeout)
		await self.raw('USER {0} 0 * :{1}'.format(identity['user'], identity['real']))
		await self.raw('NICK ' + identity['nick'])
		await self.listen()
		for item in self.loops:
			if self.loops[item]:
				self.loops[item].cancel()
		for item in [rm for rm in self.snapshot if not self.snapshot[rm]]:
			del self.snapshot[item]
		with open(f'logs/{self.server.split()[0]}.json', 'w') as fp:
			json.dump(self.snapshot, fp)
		if '|' in self.server:
			debug(self.server + 'finished scanning')
		else:
			debug(self.server.ljust(18) + ' | finished scanning')

	async def loop_initial(self):
		try:
			await asyncio.sleep(throttle.delay)
			login = {
				'pass': settings.ns_pass if settings.ns_pass else rndnick(),
				'mail': settings.ns_mail if settings.ns_mail else '{rndnick()}@{rndnick()}.'+random.choice(('com','net','org'))
			}
			for command in ('ADMIN', 'VERSION', 'LINKS', 'MAP', 'PRIVMSG NickServ :REGISTER {0} {1}'.format(login['pass'], login['mail']), 'LIST'):
				try:
					await self.raw(command)
				except:
					break
				else:
					await asyncio.sleep(1.5)
			if not self.channels['all']:
				error(self.server + 'no channels found')
				await self.raw('QUIT')
		except asyncio.CancelledError:
			pass

	async def loop_channels(self):
		try:
			while self.channels['all']:
				while len(self.channels['current']) >= throttle.channels:
					await asyncio.sleep(1)
				chan = random.choice(self.channels['all'])
				self.channels['all'].remove(chan)
				try:
					await self.raw('JOIN ' + chan)
				except:
					break
				else:
					await asyncio.sleep(throttle.join)
					del self.cchannels[chan]
			while self.nicks['check']:
				await asyncio.sleep(1)
			self.loops['nick'].cancel()
			await self.raw('QUIT')
		except asyncio.CancelledError:
			pass

	async def loop_whois(self):
		try:
			while True:
				if self.nicks['check']:
					nick = random.choice(self.nicks['check'])
					self.nicks['check'].remove(nick)
					debug(self.server + 'WHOIS ' + nick)
					try:
						await self.raw('WHOIS ' + nick)
					except:
						break
					else:
						await asyncio.sleep(throttle.whois)
				else:
					await asyncio.sleep(1)
		except asyncio.CancelledError:
			pass

	async def listen(self):
		while not self.reader.at_eof():
			try:
				data = await asyncio.wait_for(self.reader.readuntil(b'\r\n'), throttle.ztimeout)
				line = data.decode('utf-8').strip()
				#debug(line)
				args = line.split()
				numeric = args[1]
				if line.startswith('ERROR :Closing Link:'):
					raise Exception('Connection has closed.')
				elif args[0] == 'PING':
					await self.raw('PONG ' + args[1][1:])
				elif numeric == '001': #RPL_WELCOME
					host = args[0][1:]
					self.snapshot['server'] = self.server
					self.snapshot['host']   = host
					if len(host) > 25:
						self.server = f'{self.server.ljust(18)} | {host[:25]} | '
					else:
						self.server = f'{self.server.ljust(18)} | {host.ljust(25)} | '
					debug(self.server + 'connected')
					self.loops['init'] = asyncio.create_task(self.loop_initial())
				elif numeric == '322' and len(args) >= 5: # RPL_LIST
					chan  = args[3]
					users = args[4]
					self.channels['all'].append(chan)
					self.cchannels[chan] = users
				elif numeric == '323': # RPL_LISTEND
					if self.channels['all']:
						debug(self.server + 'found {0} channel(s)'.format(str(len(self.channels['all']))))
						self.loops['chan'] = asyncio.create_task(self.loop_channels())
						self.loops['nick'] = asyncio.create_task(self.loop_whois())
				elif numeric == '352' and len(args) >= 8: # RPL_WHORPL
					nick = args[7]
					if nick not in self.nicks['all']:
						self.nicks['all'].append(nick)
						self.nicks['check'].append(nick)
				elif numeric == '366' and len(args) >= 4: # RPL_ENDOFNAMES
					chan = args[3]
					self.channels['current'].append(chan)
					if chan in self.cchannels:
						debug(self.server + f'scanning {self.cchannels[chan].ljust(4)} users in {chan}')
					else:
						debug(self.server + f'scanning      users in {chan}')
					await self.raw('WHO ' + chan)
					await asyncio.sleep(throttle.part)
					await self.raw('PART ' + chan)
					self.channels['current'].remove(chan)
				elif numeric == '421' and len(args) >= 3: # ERR_UNKNOWNCOMMAND
					msg = ' '.join(args[2:])
					if 'You must be connected for' in msg:
						error(self.server + 'delay found', msg)
				elif numeric == '433': # ERR_NICKINUSE
					if not settings.nickname:
						await self.raw('NICK ' + rndnick())
					else:
						await self.raw('NICK ' + settings.nickname + str(random.randint(1000,9999)))
				elif numeric == '465': # ERR_YOUREBANNEDCREEP
					if 'dronebl' in line:
						error(self.server + 'dronebl detected')
				elif numeric == '464': # ERR_PASSWDMISMATCH
					error(self.server + 'network has a password')
				elif numeric == 'NOTICE' and len(args) >= 4:
					nick = args[0].split('!')[1:]
					msg  = ' '.join(args[3:])[1:]
					if nick == 'NickServ':
						self.snapshot['services'] = True
					for i in ('You must have been using this nick for','You must be connected for','not connected long enough','Please wait', 'You cannot list within the first'):
						if i in msg:
							error(self.server + 'delay found', msg)
				elif numeric == 'PRIVMSG' and len(args) >= 4:
					nick = args[0].split('!')[0][1:]
					msg  = ' '.join(args[3:])[1:]
					if nick == 'NickServ':
						self.snapshot['services'] = True
					if msg[:8] == '\001VERSION':
						version = random.choice('http://www.mibbit.com ajax IRC Client','mIRC v6.35 Khaled Mardam-Bey','xchat 0.24.1 Linux 2.6.27-8-eeepc i686','rZNC Version 1.0 [02/01/11] - Built from ZNC','thelounge v3.0.0 -- https://thelounge.chat/')
						await self.raw(f'NOTICE {nick} \001VERSION {version}\001')
				if numeric in self.snapshot:
					if not self.snapshot[numeric]:
						self.snapshot[numeric] = line
					elif line not in self.snapshot[numeric]:
						if type(self.snapshot[numeric]) == list:
							self.snapshot[numeric].append(line)
						elif type(self.snapshot[numeric]) == str:
							self.snapshot[numeric] = [self.snapshot[numeric], line]
				else:
					self.snapshot['raw'].append(line)
			except (UnicodeDecodeError, UnicodeEncodeError):
				pass
			except Exception as ex:
				if '|' in self.server:
					error(self.server + 'fatal error occured', ex)
				else:
					error(self.server.ljust(18) + 'fatal error occured', ex)
				break

async def main(targets):
	sema = asyncio.BoundedSemaphore(throttle.threads) # B O U N D E D   S E M A P H O R E   G A N G
	jobs = list()
	for target in targets:
		jobs.append(asyncio.ensure_future(probe(target, sema).run()))
	await asyncio.gather(*jobs)

# Main
print('#'*56)
print('#{:^54}#'.format(''))
print('#{:^54}#'.format('Internet Relay Chat Probe (IRCP)'))
print('#{:^54}#'.format('Developed by acidvegas in Python'))
print('#{:^54}#'.format('https://git.acid.vegas/ircp'))
print('#{:^54}#'.format(''))
print('#'*56)
if len(sys.argv) != 2:
	raise SystemExit('error: invalid arguments')
else:
	targets_file = sys.argv[1]
if not os.path.isfile(targets_file):
	raise SystemExit('error: invalid file path')
else:
	targets = [line.rstrip() for line in open(targets_file).readlines() if line]
	found   = len(targets)
	debug(f'loaded {found:,} targets')
	targets = [target for target in targets if not os.path.isfile(f'logs/{target}.json')] # Do not scan targets we already have logged for
	if len(targets) < found:
		debug(f'removed {found-len(targets):,} targets we already have logs for already')
	random.shuffle(targets)
	try:
		os.mkdir('logs')
	except FileExistsError:
		pass
	loop = asyncio.get_event_loop()
	loop.run_until_complete(main(targets))
	debug('IRCP has finished probing!')