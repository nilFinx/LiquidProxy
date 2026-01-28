EXE :=
ifeq ($(OS),Windows_NT)
	EXE := .exe
endif

all: build

dev:
	go run main.go
run:
	liquidproxy$(EXE) $(ARGS) $(HTTP-ARGS)

clean:
	rm -f liquidproxy*
	rm -fr builds/

build:
	go build

build-%:
	OS=$(word 1,$(subst -, ,$*)) ; \
	ARCH=$(word 2,$(subst -, ,$*)) ; \
	EXT=$$( [ "$$OS" = "windows" ] && echo ".exe" ) ; \
	GOOS=$$OS GOARCH=$$ARCH go build -o builds/liquidproxy-$*$$EXT

cross: build-darwin-amd64 build-darwin-arm64 build-linux-amd64 build-linux-arm64 build-windows-amd64