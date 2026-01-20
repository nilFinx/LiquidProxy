EXE :=
ifeq ($(OS),Windows_NT)
	EXE := .exe
endif

all: build

run:
	$(MAKE) -j2 run-job

run-job: http imap

http:
	build/HTTP$(EXE)
imap:
	build/IMAP$(EXE)

build: http-build imap-build

http-build:
	go build -o build/HTTP$(EXE) src/HTTP/main.go
imap-build:
	go build -o build/IMAP$(EXE) src/IMAP/main.go