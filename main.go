package main

import (
	log "demon/internal/logger"
	scan "demon/internal/scan"
	"os"
)

func main() {

	file, fileerr := os.OpenFile("./log/demon.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if fileerr != nil {
		panic(fileerr)
	}
	logger := log.NewLog(file, log.InfoLevel)

	ip := "192.168.199.235"
	port_str := "3306~3308"
	var ports []int
	var err error
	var isopen bool
	s := scan.NewScan(ip, port_str)
	ports, err = s.ParsePort(port_str)
	if err != nil {
		logger.Error("ParsePort", log.String("error", err.Error()))
	} else {
		for i := 0; i < len(ports); i++ {
			isopen, _ = s.CheckPortOpen(ip, ports[i])
			// if err != nil {
			// 	fmt.Println("CheckPort:", err.Error())
			// }
			if isopen {
				logger.Info("找到漏洞", log.Int("port", ports[i]), log.Bool("open", isopen))
				s.AttackSolution(ports[i], logger)
			}
		}
	}

}
