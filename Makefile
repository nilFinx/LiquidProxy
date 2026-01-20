all: build

run:
	$(MAKE) -j2 run-job

run-job: http imap

http:
	build/Liquid-HTTP-Proxy
imap:
	build/Liquid-IMAP-Proxy

build: http-build imap-build

http-build:
	go build -o build/ src/Liquid-HTTP-Proxy.go
imap-build:
	go build -o build/ src/Liquid-IMAP-Proxy.go