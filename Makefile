EXE :=
ifeq ($(OS),Windows_NT)
	EXE := .exe
endif

all: build

dev:
	$(MAKE) build
	$(MAKE) run

run:
	aquaproxy$(EXE) $(ARGS) $(HTTP-ARGS)

build:
	cd src && \
		go build -o ../
