# LiquidProxy

Based on code from [WowFunHappy's Aqua Proxy](https://github.com/wowfunhappy/aquaproxy) which is based on [kr's mitm](https://github.com/kr/mitm).

getcertpage.html uses CSS from [cydia.saurik.com](https://cydia.saurik.com/), and few parts of it is taken from Victor Lobe's personal website. ([gh/victorlobe/victorlobe.me](https://github.com/victorlobe/victorlobe.me))

This is pretty much just a rebrand of AquaProxy with some convenience.

## RISK WARNING

Do NOT use any third party instanced of LiquidProxy, unless you trust them. Due to nature of TLS MitM proxies, the server owner is able to see everything that goes through the proxy.

## How to use (on server)

Run `make`, and you'll see HTTP and IMAP in build directory. Just run it.

If you can't have GNU Make for some reason, just run `go build -o build/http.exe src/http/main.go` (replace .exe with nothing on Mac/Linux!!!), and replace http on the command with mail and do it again.

Configuration can be done through CLI, or flags.txt.

flags.txt works like a text file full of arguments:

``` txt
--debug -remove-prefix
--http-port=2141
```

## How to use (on iDevice)

### HTTP(S)

* Go to settings > Wi-Fi > (the symbol > next to WiFi network), and set proxy to manual.
* * The host/IP should be the IP/domain to your server running the proxy. Port is 6531.
* Go to [liquidproxy.r.e.a.l](https://liquidproxy.r.e.a.l/), tap "Get LiquidProxy certificate"
* Tap Install, and skip any potential warning
* * Enter passcode when prompted. This does NOT get sent to us, or the server admin.

### IMAP/SMTP

Set username to `username@domain.com@insert.mail.server.com`

If the username is just username, use `username@insert.mail.server.com`.

For Apple, it looks like `johndoe@imap.mail.me.com`

Set the port to 6532 for IMAP, 6533 for SMTP.

Disable SSL when asked. YES, YOUR MAIL GOES THROUGH UNENCRYPTED. THIS IS A HUGE SECURITY RISK IF YOU DON'T TRUST THE CONNECTION FROM YOU TO THE SERVER.

PUBLIC OR WEP WIFI, ROUTER,  CAN SEE EVERYTHING.

## About no-mitm.txt

Top part is required for certain functions to work. Bottom is something that doesn't exist anymore, so the log spam is less annoying.

## AI disclosure

AI was barely used in making of this software. It was used for some parts, but the work was mostly from reading the docs.

There are some AI? traces on the code - and .claude on .gitignore. They likely come from the original project, not me. (likely AquaProxy, not mitm)
