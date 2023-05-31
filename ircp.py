#!/usr/bin/env python
# internet relay chat probe for https://internetrelaychat.org/ - developed by acidvegas in python (https://git.acid.vegas/ircp)

import asyncio
import copy
import json
import os
import random
import ssl
import sys
import time

class settings:
	daemon      = False                        # Run in daemon mode (24/7 throttled scanning)
	errors      = True                         # Show errors in console
	errors_conn = False                        # Show connection errors in console
	log_max     = 5000000                      # Maximum log size (in bytes) before starting another
	nickname    = 'IRCP'                       # None = random
	username    = 'ircp'                       # None = random
	realname    = 'scan@internetrelaychat.org' # None = random
	ns_mail     = 'scan@internetrelaychat.org' # None = random@random.[com|net|org]
	ns_pass     = 'changeme'                   # None = random
	vhost       = None                         # Bind to a specific IP address

class throttle:
	channels = 3   if not settings.daemon else 2   # Maximum number of channels to scan at once
	delay    = 300 if not settings.daemon else 600 # Delay before registering nick (if enabled) & sending /LIST
	join     = 10  if not settings.daemon else 30  # Delay between channel JOINs
	nick     = 300 if not settings.daemon else 600 # Delay between every random NICK change
	part     = 10  if not settings.daemon else 30  # Delay before PARTing a channel
	seconds  = 300 if not settings.daemon else 600 # Maximum seconds to wait when throttled for JOIN
	threads  = 100 if not settings.daemon else 25  # Maximum number of threads running
	timeout  = 30  if not settings.daemon else 60  # Timeout for all sockets
	whois    = 5   if not settings.daemon else 15  # Delay between WHOIS requests
	ztimeout = 200 if not settings.daemon else 300 # Timeout for zero data from server

donotscan = (
	'irc.dronebl.org',       'irc.alphachat.net',
	'5.9.164.48',            '45.32.74.177',          '104.238.146.46',               '149.248.55.130',
	'2001:19f0:6001:1dc::1', '2001:19f0:b001:ce3::1', '2a01:4f8:160:2501:48:164:9:5', '2001:19f0:6401:17c::1'
)

snapshot = {
	'server'   : None,
	'host'     : None,
	'services' : False,
	'ssl'      : False,
	'proxy'    : False,
	'raw'      : [], # all other data goes in here
	'CAP'      : None,
	'KILL'     : None, # TODO: currently does not verify it was us being killed
	'NOTICE'   : None,

	# server information
	'001' : None, # RPL_WELCOME
	'002' : None, # RPL_YOURHOST
	'003' : None, # RPL_CREATED
	'004' : None, # RPL_MYINFO
	'005' : None, # RPL_ISUPPORT #TODO:  lots of useful information here can be parsed for fine tuning throttles
	'006' : None, # RPL_MAP
	'018' : None, # RPL_MAPUSERS
	'257' : None, # RPL_ADMINLOC1
	'258' : None, # RPL_ADMINLOC2
	'259' : None, # RPL_ADMINEMAIL
	'351' : None, # RPL_VERSION
	'364' : None, # RPL_LINKS
	'371' : None, # RPL_INFO
	'372' : None, # RPL_MOTD
	'304' : None, # RPL_TEXT

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
	'439' : None, # ERR_TARGETTOOFAST
	'405' : None, # ERR_TOOMANYCHANNELS (TODO: Maybe reference MAXCHANNELS= in 005 responses)
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
	'451' : None, # ERR_NOTREGISTERED (TODO: Do we need to raise an exception for this numeric?
	'464' : None, # ERR_PASSWDMISMATCH
	'465' : None, # ERR_YOUREBANNEDCREEP
	'466' : None, # ERR_YOUWILLBEBANNED
	'421' : None  # ERR_UNKNOWNCOMMAND
}

def backup(name):
	try:
		with tarfile.open(f'backup/{name}.tar.gz', 'w:gz') as tar:
			for log in os.listdir('logs'):
				tar.add('logs/' + log)
		debug('\033[1;32mBACKUP COMPLETE\033[0m')
		for log in os.listdir('logs'):
			os.remove('logs/' + log)
	except Exception as ex:
		error('\033[1;31mBACKUP FAILED\033[0m', ex)

def debug(data):
	print('{0} \033[30m|\033[0m [\033[35m~\033[0m] {1}'.format(time.strftime('%I:%M:%S'), data))

def error(data, reason=None):
	if settings.errors:
		print('{0} \033[30m|\033[0m [\033[31m!\033[0m] {1} \033[30m({2})\033[0m'.format(time.strftime('%I:%M:%S'), data, str(reason))) if reason else print('{0} \033[30m|\033[0m [\033[31m!\033[0m] {1}'.format(time.strftime('%I:%M:%S'), data))

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
		self.display   = server.ljust(18)+' \033[30m|\033[0m unknown network           \033[30m|\033[0m '
		self.semaphore = semaphore
		self.nickname  = None
		self.snapshot  = {'raw':list()}
		self.multi     = ''
		self.channels  = {'all':list(), 'current':list(), 'users':dict()}
		self.nicks     = {'all':list(), 'check':list()}
		self.loops     = {'init':None, 'chan':None, 'nick':None, 'whois':None}
		self.jthrottle = throttle.join
		self.reader    = None
		self.write     = None

	async def run(self):
		async with self.semaphore:
			try:
				await self.connect()
			except Exception as ex:
				if settings.errors_conn:
					error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect using SSL/TLS', ex)
				try:
					await self.connect(True)
				except Exception as ex:
					if settings.errors_conn:
						error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect', ex)

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
		self.nickname = identity['nick']
		self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(**options), throttle.timeout)
		del options
		if not fallback:
			self.snapshot['ssl'] = True
		await self.raw('USER {0} 0 * :{1}'.format(identity['user'], identity['real']))
		await self.raw('NICK ' + identity['nick'])
		del identity
		await self.listen()
		for item in self.loops:
			if self.loops[item]:
				self.loops[item].cancel()
		with open(f'logs/{self.server}.json{self.multi}', 'w') as fp:
			json.dump(self.snapshot, fp)
		debug(self.display + 'finished scanning')

	async def loop_initial(self):
		try:
			await asyncio.sleep(throttle.delay)
			login = {
				'pass': settings.ns_pass if settings.ns_pass else rndnick(),
				'mail': settings.ns_mail if settings.ns_mail else f'{rndnick()}@{rndnick()}.'+random.choice(('com','net','org'))
			}
			cmds = ['ADMIN', 'CAP LS', 'INFO', 'IRCOPS', 'LINKS', 'MAP', 'MODULES -all', 'STATS p', 'VERSION']
			random.shuffle(cmds)
			cmds += ['PRIVMSG NickServ :REGISTER {0} {1}'.format(login['pass'], login['mail']), 'LIST']
			for command in cmds:
				try:
					await self.raw(command)
				except:
					break
				else:
					await asyncio.sleep(1.5)
			del login
			if not self.channels['all']:
				error(self.display + '\033[31merror\033[0m - no channels found')
				await self.raw('QUIT')
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_initial', ex)

	async def loop_channels(self):
		try:
			while self.channels['all']:
				while len(self.channels['current']) >= throttle.channels:
					await asyncio.sleep(1)
				await asyncio.sleep(self.jthrottle)
				chan = random.choice(self.channels['all'])
				self.channels['all'].remove(chan)
				try:
					await self.raw('JOIN ' + chan)
				except:
					break
			self.loops['nick'].cancel()
			while self.nicks['check']:
				await asyncio.sleep(1)
			self.loops['whois'].cancel()
			del self.loops['whois']
			await self.raw('QUIT')
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_channels', ex)

	async def loop_nick(self):
		try:
			while True:
				await asyncio.sleep(throttle.nick)
				self.nickname = rndnick()
				await self.raw('NICK ' + self.nickname)
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_nick', ex)

	async def loop_whois(self):
		try:
			while True:
				if self.nicks['check']:
					nick = random.choice(self.nicks['check'])
					self.nicks['check'].remove(nick)
					try:
						await self.raw('WHOIS ' + nick)
					except:
						break
					else:
						del nick
						await asyncio.sleep(throttle.whois)
				else:
					await asyncio.sleep(1)
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_whois', ex)

	async def listen(self):
		while True:
			try:
				if self.reader.at_eof(): # TODO: can we use while self.reader.at_eof() outside of the try block?
					break
				data    = await asyncio.wait_for(self.reader.readuntil(b'\r\n'), throttle.ztimeout)
				line    = data.decode('utf-8').strip()
				args    = line.split()
				numeric = args[1]
				#debug(line)
				if sys.getsizeof(self.snapshot) >= settings.log_max: # TODO: Should we be checking this on every line of data from the server? Need to avoid asyncronous collisions possibly if not
					with open(f'logs/{self.server}.json{self.multi}', 'w') as fp:
						json.dump(self.snapshot, fp)
					self.snapshot = {'raw':list()}
					self.multi = '.1' if not self.multi else '.' + str(int(self.multi[1:])+1)
				if numeric in snapshot:
					if numeric not in self.snapshot:
						self.snapshot[numeric] = line
					elif line not in self.snapshot[numeric]:
						if type(self.snapshot[numeric]) == list:
							self.snapshot[numeric].append(line)
						elif type(self.snapshot[numeric]) == str:
							self.snapshot[numeric] = [self.snapshot[numeric], line]
				else:
					self.snapshot['raw'].append(line)
				if numeric in ('405','470','471','473','747','475','477','489','519','520') and len(args) >= 5:
					chan = args[3]
					msg = ' '.join(args[4:])[1:]
					if chan in self.channels['users']:
						del self.channels['users'][chan]
					error(f'{self.display}\033[31merror\033[0m - {chan}', msg)
				elif line.startswith('ERROR :Closing Link') and 'dronebl' in line.lower():
					self.snapshot['proxy'] = True
					error(self.display + '\033[93mDroneBL detected\033[30m')
					raise Exception('DroneBL')
				elif line.startswith('ERROR :Closing Link'):
					raise Exception('Banned')
				elif line.startswith('ERROR :Trying to reconnect too fast') or line.startswith('ERROR :Your host is trying to (re)connect too fast') or line.startswith('ERROR :Reconnecting too fast'):
					raise Exception('Throttled')
				elif line.startswith('ERROR :Access denied'):
					raise Exception('Access denied')
				elif args[0] == 'PING':
					await self.raw('PONG ' + args[1][1:])
				elif numeric == '001': #RPL_WELCOME
					host = args[0][1:]
					self.snapshot['server'] = self.server
					self.snapshot['host']   = host
					if len(host) > 25:
						self.display = f'{self.server.ljust(18)} \033[30m|\033[0m {host[:22]}... \033[30m|\033[0m '
					else:
						self.display = f'{self.server.ljust(18)} \033[30m|\033[0m {host.ljust(25)} \033[30m|\033[0m '
					debug(self.display + '\033[1;32mconnected\033[0m')
					self.loops['init'] = asyncio.create_task(self.loop_initial())
				elif numeric == '311' and len(args) >= 4: # RPL_WHOISUSER
					nick = args[3]
					if 'open proxy' in line.lower() or 'proxy monitor' in line.lower():
						self.snapshot['proxy'] = True
						error(self.display + '\033[93mProxy Monitor detected\033[30m')
					else:
						debug(f'{self.display}\033[34mWHOIS\033[0m {nick}')
				elif numeric == '322' and len(args) >= 4: # RPL_LIST
					chan  = args[3]
					users = args[4]
					if users != '0': # no need to JOIN empty channels...
						self.channels['all'].append(chan)
						self.channels['users'][chan] = users
				elif numeric == '323': # RPL_LISTEND
					if self.channels['all']:
						del self.loops['init']
						debug(self.display + '\033[36mLIST\033[0m found \033[93m{0}\033[0m channel(s)'.format(str(len(self.channels['all']))))
						self.loops['chan']  = asyncio.create_task(self.loop_channels())
						self.loops['nick']  = asyncio.create_task(self.loop_nick())
						self.loops['whois'] = asyncio.create_task(self.loop_whois())
				elif numeric == '352' and len(args) >= 8: # RPL_WHORPL
					nick = args[7]
					if nick not in self.nicks['all']+['BOPM','ChanServ','HOPM']:
						self.nicks['all'].append(nick)
						self.nicks['check'].append(nick)
				elif numeric == '366' and len(args) >= 4: # RPL_ENDOFNAMES
					chan = args[3]
					self.channels['current'].append(chan)
					debug('{0}\033[32mJOIN\033[0m {1} \033[30m(found \033[93m{2}\033[30m users)\033[0m'.format(self.display, chan, self.channels['users'][chan]))
					del self.channels['users'][chan]
					await self.raw('WHO ' + chan)
					await asyncio.sleep(throttle.part)
					await self.raw('PART ' + chan)
					self.channels['current'].remove(chan)
				elif numeric == '421' and len(args) >= 3: # ERR_UNKNOWNCOMMAND
					msg = ' '.join(args[2:])
					if 'You must be connected for' in msg:
						error(self.display + '\033[31merror\033[0m - delay found', msg)
				elif numeric == '433': # ERR_NICKINUSE
					if not settings.nickname:
						await self.raw('NICK ' + rndnick())
					else:
						await self.raw('NICK ' + settings.nickname + str(random.randint(1000,9999)))
				elif numeric == '439' and len(args) >= 5: # ERR_TARGETTOOFAST
					chan = args[3]
					msg  = ' '.join(args[4:])[1:]
					self.channels['all'].append(chan)
					if 'Target change too fast' in msg and len(args) >= 11:
						seconds = args[10]
						if seconds.isdigit():
							seconds = int(seconds)
							self.jthrottle = throttle.seconds if seconds > throttle.seconds else seconds
					error(self.display + '\033[31merror\033[0m - delay found', msg)
				elif numeric == '465': # ERR_YOUREBANNEDCREEP
					if 'dronebl' in line.lower():
						self.snapshot['proxy'] = True
						error(self.display + '\033[93mDroneBL detected\033[30m')
						raise Exception('DroneBL')
					else:
						raise Exception('K-Lined')
				elif numeric == '464': # ERR_PASSWDMISMATCH
					raise Exception('Network has a password')
				elif numeric == '487': # ERR_MSGSERVICES
					if '"/msg NickServ" is no longer supported' in line:
						login = {
							'pass': settings.ns_pass if settings.ns_pass else rndnick(),
							'mail': settings.ns_mail if settings.ns_mail else f'{rndnick()}@{rndnick()}.'+random.choice(('com','net','org'))
						}
						await self.raw('/NickServ REGISTER {0} {1}'.format(login['pass'], login['mail']))
				elif numeric == 'KILL':
					nick = args[2]
					if nick == self.nickname:
						raise Exception('KILL')
					else:
						if 'KILL' in self.snapshot:
							del self.snapshot['KILL']
				elif numeric in ('NOTICE','PRIVMSG') and len(args) >= 4:
					nick   = args[0].split('!')[1:]
					target = args[2]
					msg    = ' '.join(args[3:])[1:]
					if target == self.nickname:
						for i in ('proxy','proxys','proxies'):
							if i in msg.lower():
								self.snapshot['proxy'] = True
								check = [ x for x in ('bopm','hopm') if x in line]
								if check:
									error(f'{self.display}\033[93m{check.upper()} detected\033[30m')
								else:
									error(self.display + '\033[93mProxy Monitor detected\033[30m')
						for i in ('You must have been using this nick for','You must be connected for','not connected long enough','Please wait', 'You cannot list within the first'):
							if i in msg:
								error(self.display + '\033[31merror\033[0m - delay found', msg)
								break
						if msg[:8] == '\001VERSION':
							version = random.choice(('http://www.mibbit.com ajax IRC Client','mIRC v6.35 Khaled Mardam-Bey','xchat 0.24.1 Linux 2.6.27-8-eeepc i686','rZNC Version 1.0 [02/01/11] - Built from ZNC','thelounge v3.0.0 -- https://thelounge.chat/'))
							await self.raw(f'NOTICE {nick} \001VERSION {version}\001')
						elif nick == 'NickServ':
							self.snapshot['services'] = True
						elif '!' not in args[0]:
							if 'dronebl.org/lookup' in msg:
								self.snapshot['proxy'] = True
								error(self.display + '\033[93mDroneBL detected\033[0m')
								raise Exception('DroneBL')
							else:
								if [i for i in ('You\'re banned','You are permanently banned','You are banned','You are not welcome') if i in msg]:
									raise Exception('K-Lined')
			except (UnicodeDecodeError, UnicodeEncodeError):
				pass
			except Exception as ex:
				error(self.display + '\033[1;31mdisconnected\033[0m', ex)
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
	try:
		os.mkdir('logs')
	except FileExistsError:
		pass
	targets = [line.rstrip() for line in open(targets_file).readlines() if line and line not in donotscan]
	found   = len(targets)
	debug(f'loaded {found:,} targets')
	if settings.daemon:
		try:
			os.mkdir('backup')
		except FileExistsError:
			pass
	else:
		targets = [target for target in targets if not os.path.isfile(f'logs/{target}.json')] # Do not scan targets we already have logged for
	if len(targets) < found:
		debug(f'removed {found-len(targets):,} targets we already have logs for already')
	del found, targets_file
	while True:
		random.shuffle(targets)
		loop = asyncio.get_event_loop()
		loop.run_until_complete(main(targets))
		debug('IRCP has finished probing!')
		if settings.daemon:
			backup(time.strftime('%y%m%d-%H%M%S'))
		else:
			break