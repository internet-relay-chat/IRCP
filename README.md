# Internet Relay Chat Probe (IRCP)

![](.screens/ircp.png)

A robust information gathering tool for large scale reconnaissance on [Internet Relay Chat](https://en.wikipedia.org/wiki/Internet_Relay_Chat) servers, made for future usage with [internetrelaychat.org](https://internetrelaychat.org) for public statistics on the protocol.

Meant to be used in combination with [masscan](https://github.com/robertdavidgraham/masscan) checking **0.0.0.0/0** *(the entire IPv4 range)* for port **6667**.

The idea is to create a *proof-of-concept* documenting how large-scale information gathering on the IRC protocol can be malicious & invasive to privacy.

## Order of Operations
First, an attempt to connect using SSL/TLS on port 6697 is made, which if it fails, will fall back to a standard connection on port 6667.

Once connected, server information is gathered from `LUSERS`, `VERSION`, `LINKS`, `MAP`, `ADMIN`, `MOTD`, `LIST`, replies.

An attempt to register a nickname is then made by trying to contact NickServ.

Next, every channel is joined with a `WHO` command sent & every new nick found gets a `WHOIS`.

Everything is done in a heavily throttled manner for stealth to avoid detection.

## Collected Information
All of the raw data from a server is logged & stored. The categories below are stored seperately & hilight the key information we are after:

###### Server Information
| Numeric | Title          |
| ------- | -------------- |
| 001     | RPL_WELCOME    |
| 002     | RPL_YOURHOST   |
| 003     | RPL_CREATED    |
| 004     | RPL_MYINFO     |
| 005     | RPL_ISUPPORT   |
| 372     | RPL_MOTD       |
| 351     | RPL_VERSION    |
| 364     | RPL_LINKS      |
| 006     | RPL_MAP        |
| 018     | RPL_MAPUSERS   |
| 257     | RPL_ADMINLOC1  |
| 258     | RPL_ADMINLOC2  |
| 259     | RPL_ADMINEMAIL |

###### Statistics Information (LUSERS)
| Numeric | Title             |
| ------- | ----------------- |
| 250     | RPL_STATSCONN     |
| 251     | RPL_LUSERCLIENT   |
| 252     | RPL_LUSEROP       |
| 254     | RPL_LUSERCHANNELS |
| 255     | RPL_LUSERME       |
| 265     | RPL_LOCALUSERS    |
| 266     | RPL_GLOBALUSERS   |

###### Channel Information
| Numeric | Title        |
| ------- | ------------ |
| 332     | RPL_TOPIC    |
| 353     | RPL_NAMREPLY |
| 322     | RPL_LIST     |

###### User Information (WHOIS/WHO)
| Numeric | Title             |
| ------- | ----------------- |
| 311     | RPL_WHOISUSER     |
| 307     | RPL_WHOISREGNICK  |
| 312     | RPL_WHOISSERVER   |
| 671     | RPL_WHOISSECURE   |
| 319     | RPL_WHOISCHANNELS |
| 320     | RPL_WHOISSPECIAL  |
| 276     | RPL_WHOISCERTFP   |
| 330     | RPL_WHOISACCOUNT  |
| 338     | RPL_WHOISACTUALLY |
| 352     | RPL_WHOREPLY      |

###### Bad Numerics
| Numeric | Title                |
| ------- | -------------------- |
| 470     | ERR_LINKCHANNEL      |
| 471     | ERR_CHANNELISFULL    |
| 473     | ERR_INVITEONLYCHAN   |
| 474     | ERR_BANNEDFROMCHAN   |
| 475     | ERR_BADCHANNELKEY    |
| 477     | ERR_NEEDREGGEDNICK   |
| 489     | ERR_SECUREONLYCHAN   |
| 519     | ERR_TOOMANYUSERS     |
| 520     | ERR_OPERONLY         |
| 464     | ERR_PASSWDMISMATCH   |
| 465     | ERR_YOUREBANNEDCREEP |
| 466     | ERR_YOUWILLBEBANNED  |
| 421     | ERR_UNKNOWNCOMMAND   |

## Preview
![](.screens/preview.png)

## Todo
* Capture `IRCOPS` & `STATS p` command outputs
* Built in identd
* Checking for IPv6 availability *(SSL= in 005 responses may help verify IPv6)*
* Support for IRC servers using old versions of SSL

## Mirrors
- [acid.vegas](https://git.acid.vegas/ircp)
- [GitHub](https://github.com/acidvegas/ircp)
- [GitLab](https://gitlab.com/acidvegas/ircp)
- [SuperNETs](https://git.supernets.org/acidvegas/ircp)