EXE :=
ifeq ($(OS),Windows_NT)
	EXE := .exe
endif

all: build

dev:
	$(MAKE) build
	$(MAKE) run

run:
	$(MAKE) -j2 run-job

run-job: http-run mail-run

http-dev:
	$(MAKE) http-build
	$(MAKE) http-run

mail-dev:
	$(MAKE) mail-build
	$(MAKE) mail-run

http-run:
	http$(EXE) $(ARGS) $(HTTP-ARGS)
mail-run:
	mail$(EXE) $(ARGS) $(MAIL-ARGS)

build: http mail

http:
	go build -o http$(EXE) src/http/main.go
mail:
	go build -o mail$(EXE) src/mail/main.go