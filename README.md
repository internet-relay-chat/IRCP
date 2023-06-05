# Internet Relay Chat Probe (IRCP)

![](.screens/ircp.png)

*TRIPLE 6 SEVEN OCULOUS*

A robust information gathering tool for large scale reconnaissance on [Internet Relay Chat](https://en.wikipedia.org/wiki/Internet_Relay_Chat) servers, made for future usage with [internetrelaychat.org](https://internetrelaychat.org) for public statistics on the protocol.

Meant to be used in combination with [masscan](https://github.com/robertdavidgraham/masscan) checking **0.0.0.0/0** *(the entire IPv4 range)* for port **6667**.

The idea is to create a *proof-of-concept* documenting how large-scale information gathering on the IRC protocol can be malicious & invasive to privacy.

## Order of Operations
First, an attempt to connect using SSL/TLS on port 6697 is made, which will fall back to a standard connection on port 6667 if it fails. The **RPL_ISUPPORT** *(005)* response is checked for the `SSL=` option to try & locate secure ports.

Once connected, server information is gathered from `ADMIN`, `CAP LS`, `MODULES -all`, `VERSION`, `IRCOPS`, `MAP`, `INFO`, `LINKS`, `STATS p`, & `LIST` replies. An attempt to register a nickname is then made by trying to contact NickServ.

Lastly, every channel is joined with a `WHO` command sent & every new nick found gets a `WHOIS` sent.

Once we have finishing scanning a server, the information found is saved to a JSON file. The data in the logs are stored in categories based on [numerics](https://raw.githubusercontent.com/internet-relay-chat/random/master/numerics.txt) *(001 is RPL_WELCOME, 322 is RPL_LIST, etc)* & events *(JOIN, MODE, KILL, etc)*.

Everything is done in a *carefully* throttled manner for stealth to avoid detection. An extensive amount research on IRC daemons, services, & common practices used by network administrators was done & has fine tuned this project to be able to evade common triggers that thwart what we are doing.

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
| `ns_pass`     | `"changeme"`                   | NickServ password *(`None` = random)*                 |
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

## Preview
![](.screens/preview.png)

## Threat Scope
While IRC is an generally unfavored chat protocol as of 2023 *(roughly 7,000 networks)*, it still has a beating heart **(over 300,000 users & channels)* with potential for user growth & active development being done on [IRCv3](https://ircv3.net/) protocol implementations.

Point is..it's is not going anywhere. With that being said, every network being on the same port leads way for a lot of potential threats:

* A new RCE is found for a very common IRC bot
* A new 0day is found for a certain IRCd version
* Old IRC daemons running versions with known CVE's
* Tracing users network/channel whereabouts
* Mass spamming attacks on every network

Mass scanning *default* ports of services is nothing new & though port 6667 is not a common target, running an IRCd on a **non-standard** port should be the **standard**. If we have learned anything in the last 10 years, using standard ports for *anything* is almost always smells like a bad idea.

![](.screens/base.png)

## Todo
* Built in identd
* Checking for IPv6 availability *(SSL= in 005 responses may help verify IPv6)*
* Support for IRC servers using old versions of SSL
* Create a seperate log for failed connections
* Ability to link multiple IRCP instances running in daemon mode together for balancing
* Remote syncing the logs to another server
* Support for handling a target list that contains host:port:ssl for networks on non-standard ports
* Give props to [bwall](https://github.com/bwall) for giving me the idea with his [ircsnapshot](https://github.com/bwall/ircsnapshot) repository
* Confirm nick registered *(most likely through MODE +r)*
* Confirm SSL/TLS connections *(most likely through "You are connected using SSL cipher" NOTICE message)*

## Mirrors
- [acid.vegas](https://git.acid.vegas/ircp)
- [GitHub](https://github.com/acidvegas/ircp)
- [GitLab](https://gitlab.com/acidvegas/ircp)
- [SuperNETs](https://git.supernets.org/acidvegas/ircp)