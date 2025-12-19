.PHONY: generate build clean run dry-run install

generate:
	go generate ./...

build: generate
	go build -o zion .

clean:
	rm -f zion *_bpfel.go *_bpfeb.go *_bpfel.o *_bpfeb.o

run: build
	sudo ./zion

dry-run: build
	sudo ./zion --no-kill --verbose

install: build
	sudo cp zion /usr/local/bin/
	@echo "Installed to /usr/local/bin/zion"
