package main

import (
	scan "demon/internal/scan"
	"fmt"
)

func main() {
	ip := "192.168.199.235"
	port_str := "3306~3700"
	var ports []int
	var err error
	var isopen bool
	s := scan.NewScan(ip, port_str)
	ports, err = s.ParsePort(port_str)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		for i := 0; i < len(ports); i++ {
			isopen, _ = s.CheckPortOpen(ip, ports[i])
			// if err != nil {
			// 	fmt.Println("CheckPort:", err.Error())
			// }
			if isopen {
				fmt.Println(ports[i], isopen)
			}
		}
	}

}
