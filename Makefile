SCAN=Scan.out
REVERSEServer=Reserver.out
REVERSEClient=Reclient.out
KEYBOARD=Keylog.out
BOOM=Boom.out
PENTEST=Pentest.out

.PHONY: build clean install help test vet cover

build:
	go build -o bin/${SCAN} demo/scan/main.go
	go build -o bin/${REVERSEServer} demo/reverse/re_server/ReverseShellServer.go
	go build -o bin/${REVERSEClient} demo/reverse/re_client/ReverseShellClient.go
	go build -o bin/${KEYBOARD} demo/keylogger/keylogger.go
	go build -o bin/${BOOM} demo/sshBoom/main.go
	go build -o bin/${PENTEST} demo/pentest/main.go

test:
	go test ./...

vet:
	go vet ./...

cover:
	go test -cover ./...

install:
	go install

clean:
	if [ -f bin/${SCAN} ] ; then rm bin/${SCAN} ; fi
	if [ -f bin/${REVERSEServer} ] ; then rm bin/${REVERSEServer} ; fi
	if [ -f bin/${REVERSEClient} ] ; then rm bin/${REVERSEClient} ; fi
	if [ -f bin/${KEYBOARD} ] ; then rm bin/${KEYBOARD} ; fi
	if [ -f bin/${BOOM} ] ; then rm bin/${BOOM} ; fi
	if [ -f bin/${PENTEST} ] ; then rm bin/${PENTEST} ; fi

help:
	@echo "make build 編譯所有執行檔到 bin/"
	@echo "make clean 清除執行檔"
	@echo "make test  執行單元測試"
	@echo "make vet   go vet 靜態檢查"
	@echo "make cover 執行測試並顯示覆蓋率"