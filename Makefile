SCAN=Scan.out
REVERSEServer=Reserver.out
REVERSEClient=Reclient.out
KEYBOARD=Keylog.out


.PHONY: build clean install help

build:
	go build -o bin/${SCAN} demo/scan/main.go
	go build -o bin/${REVERSEServer} demo/reverse/re_server/ReverseShellServer.go
	go build -o bin/${REVERSEClient} demo/reverse/re_client/ReverseShellClient.go
	go build -o bin/${KEYBOARD} demo/keylogger/keylogger.go

install:
	go install

clean:
	if [ -f bin/${SCAN} ] ; then rm bin/${SCAN} ; fi
	if [ -f bin/${REVERSEServer} ] ; then rm bin/${REVERSEServer} ; fi
	if [ -f bin/${REVERSEClient} ] ; then rm bin/${REVERSEClient} ; fi
	if [ -f bin/${KEYBOARD} ] ; then rm bin/${KEYBOARD} ; fi

help:
	@echo "make 格式化"
	@echo "make build 編譯程式碼產生執行檔"
	@echo "make clean 清除執行檔"
	@echo "make test 執行單元測試"
	@echo "make check 格式化go程式碼"
	@echo "make cover 檢查測試程式碼的覆蓋率"
	@echo "make run 直接跑程式"
	@echo "make lint 程式碼檢查"
	@echo "make docker 建構docker image"