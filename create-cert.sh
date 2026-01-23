#!/bin/bash

normalcert() {
	read -p "Server IP/domain: " CN
	openssl req -x509 -newkey rsa:4096 -subj /CN=$CN/O=LiquidProxy -nodes -days 999999 -keyout LiquidProxy-key.pem -out LiquidProxy-cert.pem
	openssl req -x509 -newkey rsa:4096 -subj /CN=$CN/O=LiquidProxy -nodes -days 999999 -keyout LiquidProxy-clientKey.pem -out LiquidProxy-clientCert.pem
	openssl x509 -inform PEM -in LiquidProxy-cert.pem -outform DER -out LiquidProxy-cert.cer
}

clientcert() {
	openssl pkcs12 -export -inkey LiquidProxy-clientKey.pem -in LiquidProxy-clientCert.pem -certfile LiquidProxy-cert.pem -out LiquidProxy-client.p12 -legacy
	local ca="$(base64 -w 0 LiquidProxy-cert.pem)"
	local p12="$(base64 -w 0 LiquidProxy-client.p12)"
	sed \
			-e "s|@CA@|$ca|" \
			-e "s|@P12@|$p12|" \
			lp.plist > LiquidProxy.mobileconfig
}

main() {
	normalcert
	clientcert
}

main