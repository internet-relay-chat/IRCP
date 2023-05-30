# Internet Relay Chat Probe (IRCP)

![](.screens/ircp.png)

A robust information gathering tool for large scale reconnaissance on [Internet Relay Chat](https://en.wikipedia.org/wiki/Internet_Relay_Chat) servers, made for future usage with [internetrelaychat.org](https://internetrelaychat.org) for public statistics on the protocol.

Meant to be used in combination with [masscan](https://github.com/robertdavidgraham/masscan) checking **0.0.0.0/0** *(the entire IPv4 range)* for port **6667**.

The idea is to create a *proof-of-concept* documenting how large-scale information gathering on the IRC protocol can be malicious & invasive to privacy.

## Order of Operations
First, an attempt to connect using SSL/TLS on port 6697 is made, which if it fails, will fall back to a standard connection on port 6667.

Once connected, server information is gathered from `ADMIN`, `CAP LS`, `MODULES -all`, `VERSION`, `IRCOPS`, `MAP`, `INFO`, `LINKS`, `STATS p`, & `LIST` replies.

An attempt to register a nickname is then made by trying to contact NickServ.

Next, every channel is joined with a `WHO` command sent & every new nick found gets a `WHOIS`.

Everything is done in a heavily throttled manner for stealth to avoid detection.

## Opt-out
The IRC networks we scanned are PUBLIC networks...any person can freely connect & parse the same information. Send your hate mail to [scan@internetrelaychat.org](mailto://scan@internetrelaychat.org)

## Config
###### Settings
| Setting       | Default Value                  | Description                                           |
| ------------- | ------------------------------ | ----------------------------------------------------- |
| `errors`      | `True`                         | Show errors in console                                |
| `errors_conn` | `False`                        | Show connection errors in console                     |
| `log_max`     | `5000000`                      | Maximum log size *(in bytes)* before starting another |
| `nickname`    | `"IRCP"`                       | IRC nickname *(`None` = random)*                      |
| `username`    | `"ircp"`                       | IRC username *(`None` = random)*                      |
| `realname`    | `"internetrelaychat.org"`      | IRC realname *(`None` = random)*                      |
| `ns_mail`     | `"scan@internetrelaychat.org"` | NickServ email address *(`None` = random)*            |
| `ns_pass`     | `"changeme"`                   | NickServ password *(None = random)*                   |
| `vhost`       | `None`                         | Bind to a specific IP address                         |

###### Throttle
| Setting    | Default Value | Description                                                   |
| ---------- | ------------- | ------------------------------------------------------------- |
| `channels` | `3`           | Maximum number of channels to scan at once                    |
| `delay`    | `300`         | Delay before registering nick *(if enabled)* & sending `LIST` |
| `join`     | `10`          | Delay between channel `JOIN`                                  |
| `nick`     | `300`         | Delay between every random `NICK` change                      |
| `part`     | `10`          | Delay before `PART` from channel                              |
| `seconds`  | `300`         | Maximum seconds to wait when throttled for `JOIN`             |
| `threads`  | `100`         | Maximum number of threads running                             |
| `timeout`  | `30`          | Timeout for all sockets                                       |
| `whois`    | `5`           | Delay between `WHOIS` requests                                |
| `ztimeout` | `200`         | Timeout for zero data from server                             |

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
| 006     | RPL_MAP        |
| 018     | RPL_MAPUSERS   |
| 257     | RPL_ADMINLOC1  |
| 258     | RPL_ADMINLOC2  |
| 259     | RPL_ADMINEMAIL |
| 351     | RPL_VERSION    |
| 364     | RPL_LINKS      |
| 371     | RPL_INFO       |
| 372     | RPL_MOTD       |
| 304     | RPL_TEXT       |

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

###### Bad Numerics (channel)
| Numeric | Title              |
| ------- | ------------------ |
| 439     | ERR_TARGETTOOFAST  |
| 470     | ERR_LINKCHANNEL    |
| 471     | ERR_CHANNELISFULL  |
| 473     | ERR_INVITEONLYCHAN |
| 474     | ERR_BANNEDFROMCHAN |
| 475     | ERR_BADCHANNELKEY  |
| 477     | ERR_NEEDREGGEDNICK |
| 489     | ERR_SECUREONLYCHAN |
| 519     | ERR_TOOMANYUSERS   |
| 520     | ERR_OPERONLY       |

###### Bad Numerics (server)
| Numeric | Title                |
| ------- | -------------------- |
| 464     | ERR_PASSWDMISMATCH   |
| 465     | ERR_YOUREBANNEDCREEP |
| 466     | ERR_YOUWILLBEBANNED  |
| 421     | ERR_UNKNOWNCOMMAND   |

## Preview
![](.screens/preview.png)

## Todo
* Built in identd
* Checking for IPv6 availability *(SSL= in 005 responses may help verify IPv6)*
* Support for IRC servers using old versions of SSL

## Mirrors
- [acid.vegas](https://git.acid.vegas/ircp)
- [GitHub](https://github.com/acidvegas/ircp)
- [GitLab](https://gitlab.com/acidvegas/ircp)
- [SuperNETs](https://git.supernets.org/acidvegas/ircp)