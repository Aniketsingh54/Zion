.PHONY: generate build clean

generate:
	go generate ./...

build: generate
	go build -o zion .

clean:
	rm -f zion *_bpfel.go *_bpfeb.go *_bpfel.o *_bpfeb.o
