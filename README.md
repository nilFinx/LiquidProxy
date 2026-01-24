# LiquidProxy

Note: This repository is available in [tangled](https://tangled.org/nilfinx.tngl.sh/LiquidProxy) and [GitHub](https://github.com/nilFinx/LiquidProxy).

LiquidProxy is a fork of [WowFunHappy's Aqua Proxy](https://github.com/wowfunhappy/aquaproxy). which is based on [kr's mitm](https://github.com/kr/mitm)

getcertpage.html uses CSS from [cydia.saurik.com](https://cydia.saurik.com/), and few parts of it is taken from Victor Lobe's personal website. ([gh/victorlobe/victorlobe.me](https://github.com/victorlobe/victorlobe.me))

## What this is

* A fix for "could not start a secure connection" and other TLS/SSL issues
* Also a plaintext-to-TLS bridge for IMAP/SMTP

## What this isn't

* Complete fix for web browsing
* Secure way to do anything at all (as you're still seeing the stuff in older ciphers/SSL version)
* Re-encryption MitM bridge for IMAP/SMTP (to be added)
* Fix for (insert app name) that has completely different API by now
* Fix for (insert tweak name) fix
* A way to browse (very few) laggy websites without lag

## What this should be used for

* A normal HTTP proxy, as clients with TLSv1.3 and HTTP/2 will have the data just sent without MitM (assuming that the force-mitm flag is off)
* Get mails on ancient devices that your mail provider rejects
* Use some HTTP services with same or compatible API (such as CalDAV on strict servers like Disroot)

## Extra features

* Static web UI to quickly obtain the certificate
* Ability to block modern clients (if detected, don't rely on it)
* Ability to block ancient clients (TLSv1.1 or lower)
* Authentication (mess, but works)
* Better documentation and generally less headache of manually hosting it outside of legacy OSX
* Mail and HTTP proxy combined into one project
* Source code is split into multiple files, making maintenance easier
* Makefile for building

## RISK WARNING

Do NOT use any third party instanced of LiquidProxy, unless you trust them. Due to nature of TLS MitM proxies, the server owner is able to see everything that goes through the proxy. HTTPS WEBSITES WILL STILL BE INTERCEPTED! THERE IS NO WAY TO DEFEND AGAINST THIS RISK, OTHER THAN TO HOST YOUR OWN PROXY.

## How to use (on server/PC)

Grab the file for your OS and other-files.zip [from GitHub](https://github.com/nilFinx/LiquidProxy/releases), or follow `Compiling`. Put them all in one folder. (for zip, unzip the entire thing next to the exe.)

Run either create-cert.sh or create-cert.bat. Windows is .bat, anything else is .sh. This will create a certificate next to where it was run. The password is for encrypting the mobileconfig client certificate, and it's required.

*Make sure that OpenSSL is installed in path (if you can run `openssl` from terminal/command prompt, you do).*

After that, just open liquidproxy(.exe).

### Configuration

Configuration can be done through run arguments, or flags.txt.

flags.txt works like a text file full of arguments:

``` txt
--debug -remove-prefix
--http-port=2141
```

Enforcing password is as easy as using `--proxy-password=nilfinx:notpassword`

If you want certificate auth to be enabled, add `--enforce-cert`, although it is not known to do anything as of now.

Note: If an IP passes auth once, it will be passed forever, even when appropriate fields are not supplied.

Unfortunately, spaces are not supported at this time. Fun fact: Apple's CalDAV/CardDAV daemon politely sends the account password as proxy password, which causes an issue with authentication.

bipas.txt includes a list of websites to never prompt proxy auth for. Do NOT put common websites like google.com here. Only use this for apps that screams "pls auth proxy" because it uses account password for proxy password, like Apple's CalDAV/CardDAV daemon.

WARNING: Auth ignored (bipas.txt) requests will also count as auth pass. Do NOT add common links in bipas.txt!!

### Compiling

Run `make`, and you'll see liquidproxy(.exe) in the project directory. Just run it!

If you can't have GNU Make for some reason (there is a port of it for Windows), just run `go build -o ../` in `src` directory.

## How to use (on iDevice)

### HTTP(S)

**Note:** This might break iMessage. I already know about this, and I am trying to look for a fix. Please tell me if you found one. Do not open an issue about this.

* Go to settings > Wi-Fi > (the symbol > next to WiFi network), and set proxy to manual.
* * The host/IP should be the IP/domain to your server running the proxy. Port is 6531.
* Go to [lp.r.e.a.l](http://lp.r.e.a.l/) or [liquidproxy.r.e.a.l](http://liquidproxy.r.e.a.l/)
* * On iOS, use bundle
* * On Android, use certificate (.cer) + client cert (.p12)
* * On other, try it and see :p
* * WARN: On Windows, bundle and client cert does not work. Only other certificates does.
* Tap Install, and skip any potential warning
* * Enter passcode when prompted. This does NOT get sent to me/us, or the proxy server admin.

### IMAP/SMTP

**Note:** If you're using iCloud mail, iCloudMailFix from [Victor's Cydia repo](https://repo.victorlobe.me/) is recommended. While manual mail server adding is required like before, it does not require a proxy server.

**WARNING:** All mails are plaintext as of now. This will be fixed in future, but for now, stick with iCloud, or providers that allows older TLS version + ciphers.

Set username to `username@domain.com@insert.mail.server.com` (do NOT use double @ here)

If the username is just username, use `username@@insert.mail.server.com`. (double @ = I am not a bot for name@server)

For iCloud mail (IMAP only), it looks like `johndoe@@imap.mail.me.com`

**Note:** If your client rejects or "helps" with double @, use lp:johndoe@imap.mail.me.com instead. If it rejects double at even when separated... I don't know what to do. Open an issue and I'll figure out.

In advanced, disable SSL and set the port to 6532 for IMAP (STARTTLS), 6534 for 6532 for IMAP (direct TLS) and 6533 for SMTP.

**Note:** iOS 6 and other bad devices uses STARTTLS, even when the port is 993 by default.

## About no-mitm.txt

Top part is required for certain functions to work. Bottom is something that doesn't exist anymore, so the log spam is less annoying.

## AI disclosure

AI was barely used in making of this software. It was used for some parts, but the work was mostly from reading the docs.

There are some AI? traces on the code - and .claude on .gitignore. They likely come from the original project, not me. (likely AquaProxy, not mitm)
