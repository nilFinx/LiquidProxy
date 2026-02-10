#!/bin/bash

set -o pipefail

count=0
mode="none"

for arg in "$@"; do
	case "$arg" in
		-client|--client)
			mode="client"
			((count++))
			break
			;;
		-webui|--webui)
			mode="webui"
			((count++))
			break
			;;
		*)
			echo "unknown option: $arg (use -webui or -client)" >&2
			exit 1
			;;
	esac
done

read -p "Server IP/domain: " CN

yn() {
	# Source - https://stackoverflow.com/a
	# Posted by Myrddin Emrys, modified by community. See post 'Timeline' for change history
	# Retrieved 2026-01-28, License - CC BY-SA 4.0
	while true; do
		read -p read -p "$1 [Y/n]: " yn
		case $yn in
			[Yy]* ) break;;
			[Nn]* ) echo Done.; exit 0;;
			"" ) break;;
			* ) echo "Please answer yes or no.";;
		esac
	done
}

normalcert() {
	openssl req -x509 -newkey rsa:4096 -subj /CN=$CN/O=LiquidProxy -nodes -days 999999 -keyout LiquidProxy-key.pem -out LiquidProxy-cert.pem	
}

webuicert() {
	openssl x509 -inform PEM -in LiquidProxy-cert.pem -outform DER -out LiquidProxy-cert.cer
}

clientcert() {
	openssl req -x509 -newkey rsa:4096 -subj /CN=$CN/O=LiquidProxy -nodes -days 999999 -keyout LiquidProxy-clientKey.pem -out LiquidProxy-clientCert.pem
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
	echo nc
	if [ $mode = "none" ]; then
		yn "Do you want to generate other certificate files for web UI?"
	fi
	webuicert
	if [ $mode != "client" ]; then
		yn "Do you want to generate client certificates?"
	fi
	clientcert
}

main