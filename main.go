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

	ip := "192.168.199.123"
	port_str := "3306"
	// port_str := "3306~3308"
	// port_str := "3306-3308"
	// port_str := "3306,3308"
	// port_str := "3306|3308"
	var ports []int
	var openPort []int
	var err error
	var isopen bool
	s := scan.NewScan(ip, port_str)
	ports, err = s.ParsePort(port_str)
	if err != nil {
		logger.Error("ParsePort", log.String("error", err.Error()))
	} else {
		for i := 0; i < len(ports); i++ {
			err = s.CheckPort(ports[i])
			if err != nil {
				logger.Error("程式錯誤", log.String("error", err.Error()))
				break
			}
			isopen, _ = s.CheckPortOpen(ip, ports[i])
			if err != nil {
				logger.Error("程式錯誤", log.String("error", err.Error()))
				break
			} else {
				if isopen {
					logger.Info("找到漏洞", log.Int("port", ports[i]), log.Bool("open", isopen))
					s.PossibleVulnerability(ports[i], logger)
					openPort = append(openPort, ports[i])
				}
			}
		}
	}

	//分析開啟的Ports決定要不要試著攻擊
	for i := 0; i < len(openPort); i++ {
		s.AttackSolution(ports[i], logger)
	}
}
