# LiquidProxy

Note: This repository is available in [tangled](https://tangled.org/nilfinx.tngl.sh/LiquidProxy) and [GitHub](https://github.com/nilFinx/LiquidProxy). tangled is unstable/bleeding edge, while GitHub is stable.

LiquidProxy is a fork of [WowFunHappy's Aqua Proxy](https://github.com/wowfunhappy/aquaproxy). which is based on [kr's mitm](https://github.com/kr/mitm)

getcertpage.html uses CSS from [cydia.saurik.com](https://cydia.saurik.com/), and few parts of it is taken from Victor Lobe's personal website. ([gh/victorlobe/victorlobe.me](https://github.com/victorlobe/victorlobe.me))

## Extra features

* Static web UI to quickly obtain the certificate
* Ability to block modern clients (if detected, don't rely on it)
* Ability to block ancient clients (TLSv1.1 or lower)
* Better documentation and generally less headache of manually hosting it outside of legacy OSX
* Mail and HTTP proxy combined into one project
* Source code is split into multiple files, making maintenance easier
* Makefile for building

## RISK WARNING

Do NOT use any third party instanced of LiquidProxy, unless you trust them. Due to nature of TLS MitM proxies, the server owner is able to see everything that goes through the proxy. HTTPS WEBSITES WILL STILL BE INTERCEPTED! THERE IS NO WAY TO DEFEND AGAINST THIS RISK, OTHER THAN TO HOST YOUR OWN PROXY.

## How to use (on server/PC)

Grab the file for your OS and create-cert.sh/bat [from GitHub](https://github.com/nilFinx/LiquidProxy/releases), or follow `Compiling`.

Note: Windows is .bat, while anything else is most likely .sh.

Run either create-cert. This will create a certificate next to where it was run. Make sure that OpenSSL is installed in path (if you can run `openssl` from terminal/command prompt, you do). Alternatively, place LiquidProxy-cert.pem, LiquidProxy-cert.cer and LiquidProxy-key.pem.

Note: LiquidProxy-cert.cer is cert.pem in DER format. This is not required but recommended.

After that, just open liquidproxy(.exe).

### Configuration

Configuration can be done through run arguments, or flags.txt.

flags.txt works like a text file full of arguments:

``` txt
--debug -remove-prefix
--http-port=2141
```

### Compiling

Run `make`, and you'll see aquaproxy (.exe) in the project directory. Just run it!

If you can't have GNU Make for some reason (there is a port of it for Windows), just run `go build -o ../` in `src` directory.

## How to use (on iDevice)

### HTTP(S)

**Note:** This might break iMessage. I already know about this, and I am trying to look for a fix. Please tell me if you found one. Do not open an issue about this.

* Go to settings > Wi-Fi > (the symbol > next to WiFi network), and set proxy to manual.
* * The host/IP should be the IP/domain to your server running the proxy. Port is 6531.
* Go to [lp.r.e.a.l](https://lp.r.e.a.l/) or [liquidproxy.r.e.a.l](https://liquidproxy.r.e.a.l/), tap "Get LiquidProxy certificate"
* Tap Install, and skip any potential warning
* * Enter passcode when prompted. This does NOT get sent to me/us, or the proxy server admin.

### IMAP/SMTP

**Note:** If you're using iCloud mail, iCloudMailFix from [Victor's Cydia repo](https://repo.victorlobe.me/) is recommended. While manual mail server adding is required like before, it does not require a proxy server.

**WARNING:** All mails are plaintext as of now. This will be fixed in future, but for now, stick with iCloud, or providers that allows older TLS version + ciphers.

Set username to `username@domain.com@insert.mail.server.com`

If the username is just username, use `username@insert.mail.server.com`.

For iCloud mail (IMAP only), it looks like `johndoe@imap.mail.me.com`

In advanced, disable SSL and set the port to 6532 for IMAP, 6533 for SMTP.

## About no-mitm.txt

Top part is required for certain functions to work. Bottom is something that doesn't exist anymore, so the log spam is less annoying.

## AI disclosure

AI was barely used in making of this software. It was used for some parts, but the work was mostly from reading the docs.

There are some AI? traces on the code - and .claude on .gitignore. They likely come from the original project, not me. (likely AquaProxy, not mitm)
