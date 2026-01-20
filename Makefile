all: http imap

http:
	go build -o build/ src/Liquid-HTTP-Proxy.go

imap:
	go build -o build/ src/Liquid-IMAP-Proxy.go