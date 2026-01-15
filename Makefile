.PHONY: generate build clean run dry-run enforce install

generate:
	go generate ./...

build: generate
	go build -o zion .

clean:
	rm -f zion *_bpfel.go *_bpfeb.go *_bpfel.o *_bpfeb.o
	rm -f lsm/*_bpfel.go lsm/*_bpfeb.go lsm/*_bpfel.o lsm/*_bpfeb.o

run: build
	sudo ./zion

dry-run: build
	sudo ./zion --no-kill --verbose

enforce: build
	sudo ./zion --enforce

install: build
	sudo cp zion /usr/local/bin/
	@echo "Installed to /usr/local/bin/zion"
