#!/usr/bin/env python
# internet relay chat probe for https://internetrelaychat.org/ - developed by acidvegas in python (https://git.acid.vegas/ircp)

import asyncio
import ipaddress
import json
import os
import random
import ssl
import sys
import tarfile
import time

class settings:
	daemon      = False                        # Run in daemon mode (24/7 throttled scanning)
	errors      = True                         # Show errors in console
	errors_conn = False                        # Show connection errors in console
	log_max     = 5000000 # 5mb                # Maximum log size (in bytes) before starting another
	nickname    = 'IRCP'                       # None = random
	username    = 'ircp'                       # None = random
	realname    = 'scan@internetrelaychat.org' # None = random
	ns_mail     = 'scan@internetrelaychat.org' # None = random@random.[com|net|org]
	ns_pass     = None                         # None = random
	vhost       = None                         # Bind to a specific IP address

class throttle:
	channels = 5   if not settings.daemon else 3    # Maximum number of channels to scan at once
	commands = 1.5 if not settings.daemon else 3    # Delay bewteen multiple commands send to the same target
	connect  = 15  if not settings.daemon else 60   # Delay between each connection attempt on a diffferent port
	delay    = 300 if not settings.daemon else 600  # Delay before registering nick (if enabled) & sending /LIST
	join     = 10  if not settings.daemon else 30   # Delay between channel JOINs
	nick     = 900 if not settings.daemon else 1200 # Delay between every random NICK change
	part     = 10  if not settings.daemon else 30   # Delay before PARTing a channel
	seconds  = 300 if not settings.daemon else 600  # Maximum seconds to wait when throttled for JOIN or WHOIS
	threads  = 500 if not settings.daemon else 300  # Maximum number of threads running
	timeout  = 30  if not settings.daemon else 60   # Timeout for all sockets
	whois    = 15  if not settings.daemon else 30   # Delay between WHOIS requests
	ztimeout = 600 if not settings.daemon else 900  # Timeout for zero data from server

class bad:
	donotscan = (
		'irc.dronebl.org',       'irc.alphachat.net',
		'5.9.164.48',            '45.32.74.177',          '104.238.146.46',               '149.248.55.130',
		'2001:19f0:6001:1dc::1', '2001:19f0:b001:ce3::1', '2a01:4f8:160:2501:48:164:9:5', '2001:19f0:6401:17c::1'
	)
	chan = {
		'403' : 'ERR_NOSUCHCHANNEL',    '405' : 'ERR_TOOMANYCHANNELS',
		'435' : 'ERR_BANONCHAN',        '442' : 'ERR_NOTONCHANNEL',
		'448' : 'ERR_FORBIDDENCHANNEL', '470' : 'ERR_LINKCHANNEL',
		'471' : 'ERR_CHANNELISFULL',    '473' : 'ERR_INVITEONLYCHAN',
		'474' : 'ERR_BANNEDFROMCHAN',   '475' : 'ERR_BADCHANNELKEY',
		'476' : 'ERR_BADCHANMASK',      '477' : 'ERR_NEEDREGGEDNICK',
		'479' : 'ERR_BADCHANNAME',      '480' : 'ERR_THROTTLE',
		'485' : 'ERR_CHANBANREASON',    '488' : 'ERR_NOSSL',
		'489' : 'ERR_SECUREONLYCHAN',   '519' : 'ERR_TOOMANYUSERS',
		'520' : 'ERR_OPERONLY',         '926' : 'ERR_BADCHANNEL'
	}
	error = {
		'install identd'                 : 'Identd required',
		'trying to reconnect too fast'   : 'Throttled',
		'trying to (re)connect too fast' : 'Throttled',
		'reconnecting too fast'          : 'Throttled',
		'access denied'                  : 'Access denied',
		'not authorized to'              : 'Not authorized',
		'not authorised to'              : 'Not authorized',
		'password mismatch'              : 'Password mismatch',
		'dronebl'                        : 'DroneBL',
		'dnsbl'                          : 'DNSBL',
		'g:lined'                        : 'G:Lined',
		'z:lined'                        : 'Z:Lined',
		'timeout'                        : 'Timeout',
		'closing link'                   : 'Banned',
		'banned'                         : 'Banned',
		'client exited'                  : 'QUIT',
		'quit'                           : 'QUIT'
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
	print('{0} \033[1;30m|\033[0m [\033[35m~\033[0m] {1}'.format(time.strftime('%I:%M:%S'), data))

def error(data, reason=None):
	if settings.errors:
		print('{0} \033[1;30m|\033[0m [\033[31m!\033[0m] {1} \033[1;30m({2})\033[0m'.format(time.strftime('%I:%M:%S'), data, str(reason))) if reason else print('{0} \033[1;30m|\033[0m [\033[31m!\033[0m] {1}'.format(time.strftime('%I:%M:%S'), data))

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
	def __init__(self, semaphore, server, port, family=2):
		self.semaphore = semaphore
		self.server    = server
		self.port      = 6697
		self.oport     = port
		self.family    = family
		self.display   = server.ljust(18)+' \033[1;30m|\033[0m unknown network           \033[1;30m|\033[0m '
		self.nickname  = None
		self.multi     = ''
		self.snapshot  = dict()
		self.channels  = {'all':list(), 'current':list(), 'users':dict()}
		self.nicks     = {'all':list(), 'check':list()}
		self.loops     = {'init':None, 'chan':None, 'nick':None, 'whois':None}
		self.login     = {'pass': settings.ns_pass if settings.ns_pass else rndnick(), 'mail': settings.ns_mail if settings.ns_mail else f'{rndnick()}@{rndnick()}.'+random.choice(('com','net','org'))}
		self.services  = {'chanserv':True, 'nickserv':True}
		self.jthrottle = throttle.join
		self.nthrottle = throttle.whois
		self.reader    = None
		self.write     = None

	async def sendmsg(self, target, msg):
		await self.raw(f'PRIVMSG {target} :{msg}')

	async def run(self):
		async with self.semaphore:
			try:
				await self.connect() # 6697
			except Exception as ex:
				if settings.errors_conn:
					error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect using SSL/TLS on port ' + str(self.port), ex)
				if self.oport not in (6667,6697):
					self.port = self.oport
					await asyncio.sleep(throttle.connect)
					try:
						await self.connect() # Non-standard
					except Exception as ex:
						if settings.errors_conn:
							error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect using SSL/TLS on port ' + str(self.port), ex)
						self.port = 6667
						await asyncio.sleep(throttle.connect)
						try:
							await self.connect(True) # 6667
						except Exception as ex:
							if settings.errors_conn:
								error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect on port ' + str(self.port), ex)
							self.port = self.oport
							await asyncio.sleep(throttle.connect)
							try:
								await self.connect(True) # Non-standard
							except Exception as ex:
								if settings.errors_conn:
									error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect on port ' + str(self.port), ex)
				else:
					self.port = 6667
					await asyncio.sleep(throttle.connect)
					try:
						await self.connect(True) # 6667
					except Exception as ex:
						if settings.errors_conn:
							error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect on port ' + str(self.port), ex)

	async def raw(self, data):
		self.writer.write(data[:510].encode('utf-8') + b'\r\n')
		await self.writer.drain()

	async def connect(self, fallback=False):
		options = {
			'host'       : self.server,
			'port'       : self.port,
			'limit'      : 1024,
			'ssl'        : None if fallback else ssl_ctx(),
			'family'     : self.family,
			'local_addr' : (settings.vhost, random.randint(5000,65000)) if settings.vhost else None
		}
		identity = {
			'nick': settings.nickname if settings.nickname else rndnick(),
			'user': settings.username if settings.username else rndnick(),
			'real': settings.realname if settings.realname else rndnick()
		}
		self.nickname = identity['nick']
		self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(**options), throttle.timeout)
		self.snapshot['port'] = options['port']
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
			cmds = ['ADMIN', 'CAP LS', 'COMMANDS', 'HELP', 'INFO', 'IRCOPS', 'LINKS', 'MAP', 'MODULES -all', 'SERVLIST', 'STATS p', 'VERSION']
			random.shuffle(cmds)
			cmds += ['PRIVMSG NickServ :REGISTER {0} {1}'.format(self.login['pass'], self.login['mail']), 'PRIVMSG ChanServ :LIST *', 'PRIVMSG NickServ :LIST *', 'LIST']
			for command in cmds:
				try:
					await self.raw(command)
				except:
					break
				else:
					await asyncio.sleep(throttle.commands)
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
					if self.services['chanserv']:
						await self.sendmsg('ChanServ', 'INFO ' + chan)
						await asyncio.sleep(throttle.commands)
					await self.raw('JOIN ' + chan)
				except:
					break
			self.loops['nick'].cancel()
			while self.nicks['check']:
				await asyncio.sleep(1)
			self.loops['whois'].cancel()
			self.loops['nick'].cancel()
			await self.raw('QUIT')
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_channels', ex)

	async def loop_nick(self):
		try:
			while True:
				await asyncio.sleep(throttle.nick+random.randint(60,90))
				self.nickname = rndnick()
				await self.raw('NICK ' + self.nickname)
				debug(self.display + '\033[0;35mNICK\033[0m - new identity')
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
						await asyncio.sleep(throttle.commands)
						if self.services['nickserv']:
							await self.sendmsg('NickServ', 'INFO ' + nick)
							await asyncio.sleep(throttle.commands)
						await self.raw(f'NOTICE {nick} \001VERSION\001') # TODO: check the database if we already have this information to speed things up
						await asyncio.sleep(throttle.commands)
						await self.raw(f'NOTICE {nick} \001TIME\001')
						await asyncio.sleep(throttle.commands)
						await self.raw(f'NOTICE {nick} \001CLIENTINFO\001')
						await asyncio.sleep(throttle.commands)
						await self.raw(f'NOTICE {nick} \001SOURCE\001')
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

	async def db(self, event, data):
		if event in self.snapshot:
			if data not in self.snapshot[event]:
				self.snapshot[event].append(data)
		else:
			self.snapshot[event] = [data,]

	async def listen(self):
		while True:
			try:
				if self.reader.at_eof():
					break
				data  = await asyncio.wait_for(self.reader.readuntil(b'\r\n'), throttle.ztimeout)
				line  = data.decode('utf-8').strip()
				args  = line.split()
				event = args[1].upper()
				if sys.getsizeof(self.snapshot) >= settings.log_max:
					with open(f'logs/{self.server}.json{self.multi}', 'w') as fp:
						json.dump(self.snapshot, fp)
					self.snapshot = dict()
					self.multi = '.1' if not self.multi else '.' + str(int(self.multi[1:])+1)
				if args[0].upper() == 'ERROR':
					await self.db('ERROR', line)
				elif not event.isdigit() and event not in ('CAP','INVITE','JOIN','KICK','KILL','MODE','NICK','NOTICE','PART','PRIVMSG','QUIT','TOPIC','WHO'):
					await self.db('RAW', line)
				elif event != '401':
					await self.db(event, line)
				if event in bad.chan and len(args) >= 4:
					chan = args[3]
					if chan in self.channels['users']:
						del self.channels['users'][chan]
					error(f'{self.display}\033[31merror\033[0m - {chan}', bad.chan[event])
				elif line.startswith('ERROR :'):
					check = [check for check in bad.error if check in line.lower()]
					if check:
						if check[0] in ('dronebl','dnsbl'):
							self.snapshot['proxy'] = True
						raise Exception(bad.error[check[0]])
				elif args[0] == 'PING':
					await self.raw('PONG ' + args[1][1:])
				elif event == 'KICK' and len(args) >= 4:
					chan   = args[2]
					kicked = args[3]
					if kicked == self.nickname:
						if chan in self.channels['current']:
							self.channels['current'].remove(chan)
				elif event == 'MODE' and len(args) == 4:
					nick = args[2]
					if nick == self.nickname:
						mode = args[3][1:]
						if mode == '+r':
							self.snapshot['registered'] = self.login
				elif event == '001': #RPL_WELCOME
					host = args[0][1:]
					self.snapshot['server'] = self.server
					self.snapshot['host']   = host
					if len(host) > 25:
						self.display = f'{self.server.ljust(18)} \033[1;30m|\033[0m {host[:22]}... \033[1;30m|\033[0m '
					else:
						self.display = f'{self.server.ljust(18)} \033[1;30m|\033[0m {host.ljust(25)} \033[1;30m|\033[0m '
					debug(self.display + f'\033[1;32mconnected\033[0m \033[1;30m(port {self.port})\033[0m')
					self.loops['init'] = asyncio.create_task(self.loop_initial())
				elif event == '005':
					for item in args:
						if item.startswith('SSL=') and item[4:]:
							if not self.snapshot['ssl']:
								self.snapshot['ssl'] = item[4:]
							break
				elif event == '311' and len(args) >= 4: # RPL_WHOISUSER
					nick = args[3]
					if 'open proxy' in line.lower() or 'proxy monitor' in line.lower():
						self.snapshot['proxy'] = True
						error(self.display + '\033[93mProxy Monitor detected\033[0m', nick)
					else:
						debug(f'{self.display}\033[34mWHOIS\033[0m {nick}')
				elif event == 315 and len(args) >= 3: # RPL_ENDOFWHO
					chan = args[3]
					await self.raw(f'MODE {chan} +b')
					await asyncio.sleep(throttle.commands)
					await self.raw(f'MODE {chan} +e')
					await asyncio.sleep(throttle.commands)
					await self.raw(f'MODE {chan} +I')
					await asyncio.sleep(throttle.commands)
					await self.raw(f'NOTICE {chan} \001VERSION\001')
					await asyncio.sleep(throttle.commands)
					await self.raw(f'NOTICE {chan} \001TIME\001')
					await asyncio.sleep(throttle.commands)
					await self.raw(f'NOTICE {chan} \001CLIENTINFO\001')
					await asyncio.sleep(throttle.commands)
					await self.raw(f'NOTICE {chan} \001SOURCE\001')
					await asyncio.sleep(throttle.part)
					await self.raw('PART ' + chan)
					self.channels['current'].remove(chan)
				elif event == '322' and len(args) >= 4: # RPL_LIST
					chan  = args[3]
					users = args[4]
					if users != '0': # no need to JOIN empty channels...
						self.channels['all'].append(chan)
						self.channels['users'][chan] = users
				elif event == '323': # RPL_LISTEND
					if self.channels['all']:
						debug(self.display + '\033[36mLIST\033[0m found \033[93m{0}\033[0m channel(s)'.format(str(len(self.channels['all']))))
						self.loops['chan']  = asyncio.create_task(self.loop_channels())
						self.loops['nick']  = asyncio.create_task(self.loop_nick())
						self.loops['whois'] = asyncio.create_task(self.loop_whois())
				elif event == '352' and len(args) >= 8: # RPL_WHORPL
					nick = args[7]
					if nick not in self.nicks['all']+[self.nickname,]:
						self.nicks['all'].append(nick)
						self.nicks['check'].append(nick)
				elif event == '366' and len(args) >= 4: # RPL_ENDOFNAMES
					chan = args[3]
					self.channels['current'].append(chan)
					if chan in self.channels['users']:
						debug('{0}\033[32mJOIN\033[0m {1} \033[1;30m(found \033[93m{2}\033[1;30m users)\033[0m'.format(self.display, chan, self.channels['users'][chan]))
						del self.channels['users'][chan]
					await self.raw('WHO ' + chan)
				elif event == '401' and len(args) >= 4: # ERR_NOSUCHNICK
					nick = args[3]
					if nick == 'ChanServ':
						self.services['chanserv'] = False
					elif nick == 'NickServ':
						self.services['nickserv'] = False
					else:
						await self.raw('WHOWAS ' + nick)
				elif event == '421' and len(args) >= 3: # ERR_UNKNOWNCOMMAND
					msg = ' '.join(args[2:])
					if 'You must be connected for' in msg:
						error(self.display + '\033[31merror\033[0m - delay found', msg)
				elif event == '433': # ERR_NICKINUSE
					self.nickname = rndnick()
					await self.raw('NICK ' + self.nickname)
				elif event == '439' and len(args) >= 11: # ERR_TARGETTOOFAST
					target  = args[3]
					msg     = ' '.join(args[4:])[1:]
					seconds = args[10]
					if target[:1] in ('#','&'):
						self.channels['all'].append(target)
						if seconds.isdigit():
							self.jthrottle = throttle.seconds if int(seconds) > throttle.seconds else int(seconds)
					else:
						self.nicks['check'].append(target)
						if seconds.isdigit():
							self.nthrottle = throttle.seconds if int(seconds) > throttle.seconds else int(seconds)
					error(self.display + '\033[31merror\033[0m - delay found for ' + target, msg)
				elif event == '465' and len(args) >= 5: # ERR_YOUREBANNEDCREEP
					check = [check for check in bad.error if check in line.lower()]
					if check:
						if check[0] in ('dronebl','dnsbl'):
							self.snapshot['proxy'] = True
						raise Exception(bad.error[check[0]])
				elif event == '464': # ERR_PASSWDMISMATCH
					raise Exception('Network has a password')
				elif event == '487': # ERR_MSGSERVICES
					if '"/msg NickServ" is no longer supported' in line:
						await self.raw('/NickServ REGISTER {0} {1}'.format(self.login['pass'], self.login['mail']))
				elif event == 'KILL':
					nick = args[2]
					if nick == self.nickname:
						raise Exception('KILL')
				elif event in ('NOTICE','PRIVMSG') and len(args) >= 4:
					nick   = args[0].split('!')[1:]
					target = args[2]
					msg    = ' '.join(args[3:])[1:]
					if target == self.nickname:
						for i in ('proxy','proxys','proxies'):
							if i in msg.lower():
								self.snapshot['proxy'] = True
								check = [x for x in ('bopm','hopm') if x in line]
								if check:
									error(f'{self.display}\033[93m{check[0].upper()} detected\033[0m')
								else:
									error(self.display + '\033[93mProxy Monitor detected\033[0m')
						for i in ('You must have been using this nick for','You must be connected for','not connected long enough','Please wait', 'You cannot list within the first'):
							if i in msg:
								error(self.display + '\033[31merror\033[0m - delay found', msg)
								break
						if msg[:8] == '\001VERSION':
							version = random.choice(('http://www.mibbit.com ajax IRC Client','mIRC v6.35 Khaled Mardam-Bey','xchat 0.24.1 Linux 2.6.27-8-eeepc i686','rZNC Version 1.0 [02/01/11] - Built from ZNC','thelounge v3.0.0 -- https://thelounge.chat/'))
							await self.raw(f'NOTICE {nick} \001VERSION {version}\001')
						elif ('You are connected' in line or 'Connected securely via' in line) and ('SSL' in line or 'TLS' in line):
							cipher = line.split()[-1:][0].replace('\'','').replace('"','')
							self.snapshot['ssl_cipher'] = cipher
						elif nick in ('ChanServ','NickServ'):
							self.snapshot['services'] = True
							if 'is now registered' in msg or f'Nickname {self.nickname} registered' in msg:
								debug(self.display + '\033[35mNickServ\033[0m registered')
								self.snapshot['registered'] = self.login
						elif '!' not in args[0]:
							if 'dronebl.org/lookup' in msg:
								self.snapshot['proxy'] = True
								error(self.display + '\033[93mDroneBL detected\033[0m')
								raise Exception('DroneBL')
							else:
								if [i for i in ('You\'re banned','You are permanently banned','You are banned','You are not welcome','Temporary K-line') if i in msg]:
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
		server = ':'.join(target.split(':')[-1:])
		if ':' not in target: # TODO: IPv6 addresses without a port wont get :6667 appeneded to it like this
			port = 6697
		else:
			port  = int(':'.join(target.split(':')[:-1]))
		try:
			ipaddress.IPv4Address(server)
			jobs.append(asyncio.ensure_future(probe(sema, server, port, 2).run()))
		except:
			try:
				ipaddress.IPv6Address(server)
				jobs.append(asyncio.ensure_future(probe(sema, server, port, 10).run()))
			except:
				error('invalid ip address', server)
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
	targets = [line.rstrip() for line in open(targets_file).readlines() if line and line not in bad.donotscan]
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
		asyncio.run(main(targets))
		debug('IRCP has finished probing!')
		if settings.daemon:
			backup(time.strftime('%y%m%d-%H%M%S'))
		else:
			break
