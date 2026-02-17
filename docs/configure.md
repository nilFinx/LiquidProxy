# Configure

## Basic flags.txt setup

flags.txt is like a start.sh file - it's command line arguments, but in a file.

```txt
-allow-ssl

-block-modern-connections
--proxy-password=user:password

-http-port=3867 --no-imap-direct
```

The format is very simple: It's either `-flag` or `--flag`. Use `-flag=value` or `--flag=value` for assigning values.

Above example does the following:

* enables devices with TLSv1.1 or lower (`-allow-ssl`)
* blocks connections coming from TLSv1.3, or HTTP/2 (or higher) (`-block-modern-connections`) (HTTP proxy only, this blocks the connection after the handshake was done)
* sets HTTP proxy username to `user`, password to `password`. ( `--proxy-password=user:password` )
* sets HTTP proxy port to 3867 (`-http-port=3867`)
* disables IMAP direct TLS proxy ( `--no-imap-direct` )

More options can be seen by running liquidproxy with `--help` flag.

Enforcing password is as easy as using `--proxy-password=user:password` **and is recommended**.

Certificate auth is possible, but due to nature of legacy clients... I do not recommend it. Some web browsers are very annoying when enforcing certs. Some refuses to use it.

bipas.txt includes a list of websites to never prompt proxy auth for. Do NOT put common websites like google.com here. Only use this for apps that screams "Please give me password" which it uses account password for proxy password, like Apple's CalDAV/CardDAV daemon.

### Notes

If an IP passes auth once, it will be marked as "passed" forever, even on incorrect password, etc.

Apple's CalDAV/CardDAV daemon politely sends the account password as proxy password, which causes an issue with authentication.

Unfortunately, spaces are not supported in the password at this time.

## How to connect

### HTTP(S)

**Note:** This might break iMessage. I already know about this, and I am trying to look for a fix. Please tell me if you found one. Do not open an issue about this.

For services with TLS pinning, find the domain and add it to no-mitm.txt. PRs are welcome :)

* Go to settings > Wi-Fi > (the > symbol next to WiFi network), and set proxy to manual.
* * The host/IP should be the IP/domain to your server running the proxy. Port is 6531.
* Go to [lp.r.e.a.l](http://lp.r.e.a.l/) or [liquidproxy.r.e.a.l](http://liquidproxy.r.e.a.l/)
* For usual usage, use the `Get certificate (.pem)`or `Get certificate (.cer)` button. If you want to use client certificates, get mobileconfig bundle for Apple OSes, or .p12 client cert for others.
* * WARN: On Windows server, bundle and client cert does not work. Only server/usual certificates does.
* Tap Install, and skip any potential warning
* * Enter passcode when prompted. This does NOT get sent to me/us, or the proxy server admin.

### IMAP/SMTP

**WARNING:** iOS 6 mail appears to only support TLSv1.1. `-allow-ssl` is required.

**Note:** If you're using iCloud mail, iCloudMailFix from [Victor's Cydia repo](https://repo.victorlobe.me/) is recommended. While manual mail server adding is required like before, it does not require a proxy server.

Set username to `username@domain.com@insert.mail.server.com` (do NOT use double @ here)

If the username is just username, use `username@@insert.mail.server.com`.

For iCloud mail (IMAP only, SMTP is `username@icloud.com@smpt.mail.me.com`), it looks like `johndoe@@imap.mail.me.com`

**Note:** If your client rejects or "helps" with double @, use lp:johndoe@imap.mail.me.com instead. If it rejects double at even when separated... I don't know what to do. Open an issue and I'll figure out.

In advanced, set the port to 6532 for IMAP (STARTTLS), 6534 for IMAP (direct TLS) and 6533 for SMTP.

**Note:** iOS 6 mail and other bad clients uses STARTTLS, even when the port is 993 by default.

### GenericTCP

Create `generic-tcp.txt` with:

```txt
6569
_xmpps-client._tcp.disroot.org:5223

6568
server.service.com:6982
```

`_name._tcp` part is for utilizing SRV record, and is completely optional. If the first entry in SRV fails, it will fall back to just A record resolving.

First rule redirects port 6569 to `disroot.org`'s XMPP server (direct TLS), with whatever port+IP that the SRV record gives, or the A record IP address and port 5223.

Second redirects 6568 to the A record of `server.service.com` with port 6982. No SRV here.
