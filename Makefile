BINARY=Demon.out
REVERSE=ReverseServer.out

build:
	go build -o ${BINARY} main.go
	go build -o ${REVERSE} reverse/ReverseShellServer.go

install:
	go install

clean:
	if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi
.PHONY:  clean install