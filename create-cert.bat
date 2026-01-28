@echo off

echo WARNING: Windows version cannot generate client certs. Windows is for testing only due to this.

set /p "cn=Server IP/domain: "

openssl.exe req -x509 -newkey rsa:4096 -subj /CN=%cn%/O=LiquidProxy -nodes -days 999999 -keyout LiquidProxy-key.pem -out LiquidProxy-cert.pem
openssl.exe x509 -inform PEM -in LiquidProxy-cert.pem -outform DER -out LiquidProxy-cert.cer
