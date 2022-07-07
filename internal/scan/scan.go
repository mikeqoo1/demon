package scan

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Scan struct {
	ip   string
	port string //要驗證的端口 (範例:80 or 80,81 or 80-83 or 80~85 or 80|81|82)
}

//NewScan 產生一個掃描的物件
func NewScan(ip string, ports string) *Scan {
	//初始化
	s := &Scan{
		ip:   ip,
		port: ports,
	}
	return s
}

//ParsePort 解析Port
func (s *Scan) ParsePort(portstr string) ([]int, error) {
	var ports []int
	var err error
	var number int
	//處理 "," "-" "~" "|" 號
	if strings.Contains(portstr, ",") {
		portArr := strings.Split(portstr, ",")
		for _, v := range portArr {
			number, err = strconv.Atoi(v)
			ports = append(ports, number)
		}
	} else if strings.Contains(portstr, "|") {
		portArr := strings.Split(portstr, "|")
		for _, v := range portArr {
			number, err = strconv.Atoi(v)
			ports = append(ports, number)
		}
	} else if strings.Contains(portstr, "-") {
		portArr := strings.Split(portstr, "-")
		startPort := 0
		endPort := 0
		for k, v := range portArr {
			if k == 0 {
				number, err = strconv.Atoi(v)
				startPort = number
			} else if k == 1 {
				number, err = strconv.Atoi(v)
				endPort = number
			}
		}
		if startPort >= endPort {
			errmsg := fmt.Sprint("範圍區間有問題!!!", startPort, "-", endPort)
			err = errors.New(errmsg)
		} else {
			ports = append(ports, startPort)
			for i := 1; i <= endPort-startPort; i++ {
				ports = append(ports, startPort+i)
			}
		}
	} else if strings.Contains(portstr, "~") {
		portArr := strings.Split(portstr, "~")
		startPort := 0
		endPort := 0
		for k, v := range portArr {
			if k == 0 {
				number, err = strconv.Atoi(v)
				startPort = number
			} else if k == 1 {
				number, err = strconv.Atoi(v)
				endPort = number
			}
		}
		if startPort >= endPort {
			errmsg := fmt.Sprint("範圍區間有問題!!!", startPort, "~", endPort)
			err = errors.New(errmsg)
		} else {
			ports = append(ports, startPort)
			for i := 1; i <= endPort-startPort; i++ {
				ports = append(ports, startPort+i)
			}
		}
	} else {
		fmt.Println("不在分隔符號內!!!!")
		err = errors.New("不在分隔符號內")
	}

	return ports, err
}

//CheckPort 檢查Port合理性
func (s *Scan) CheckPort(port int) error {
	var err error
	if port < 1 || port > 65535 {
		return errors.New("端口號範圍超出")
	}
	return err
}

//CheckPortOpen 檢查Port是否被開啟
func (s *Scan) CheckPortOpen(ip string, port int) (bool, error) {
	var address string = fmt.Sprintf("%s:%d", ip, port)
	var timeout time.Duration = 100 * time.Millisecond //timeout => 100ms
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			fmt.Println("超出系統最大連線" + err.Error())
			os.Exit(1)
		}
		return false, err
	}
	conn.Close()
	return true, err
}
