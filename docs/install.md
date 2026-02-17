# Install

## Fetching the thing

Grab a file for your OS [from here](https://github.com/nilFinx/LiquidProxy/releases/).

Or, `make`

Alternatively, you can use a "simple" bash script (Thanks GitHub!) :

```sh
ver=$(curl -s https://api.github.com/repos/nilfinx/liquidproxy/releases/latest | grep -E "\"tag_name\":" | grep -oE [0-9.]+)
wget https://github.com/nilFinx/LiquidProxy/releases/download/$ver/liquidproxy-linux-arm64 -O liquidproxy
```

One-liner:

```sh
wget https://github.com/nilFinx/LiquidProxy/releases/download/$(curl -s https://api.github.com/repos/nilfinx/liquidproxy/releases/latest | grep -E "\"tag_name\":" | grep -oE [0-9.]+)/liquidproxy-linux-arm64 -O liquidproxy
```

For first time setup, you also need other-files.zip from releases.

## Path setup

Now, unzip other-files.zip in the way that all the files inside is next to the file for your OS. It should look like this:

``` txt
bipas.txt
create-cert.bat
create-cert.sh
example-flags.txt
lp.plist
no-mitm.txt
redirects.txt
```

## Creating certs

Looks good? Now, run create-cert.sh. For Windows, it is create-cert.bat.

Now, you probably have certificates in the same folder that you run it on.

Note: You need to have OpenSSL in your path (if `openssl` in cmd/terminal does not error out, you have it)

## Done

Now, continue to [Configure](./configure).
