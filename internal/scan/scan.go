package scan

import (
	log "demon/internal/logger"
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

func (s *Scan) AttackSolution(port int, logger *log.Logger) {
	if port == 21 || port == 69 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "ftp/sftp文件傳輸協議"), log.String("攻擊方式", "爆破/監聽/Buffer Overflow/後門"))
	} else if port == 22 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "ssh"), log.String("攻擊方式", "爆破OpenSSH/內網代理轉發/文件傳輸"))
	} else if port == 23 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "telnet"), log.String("攻擊方式", "爆破/監聽"))
	} else if port == 25 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "smtp邮件服務"), log.String("攻擊方式", "郵件偽造"))
	} else if port == 53 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "DNS域名系统"), log.String("攻擊方式", "DNS區域傳輸/DNS劫持/DNS污染/DNS欺騙/利用DNS隧道技術刺透防火牆"))
	} else if port == 67 || port == 68 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "dhcp"), log.String("攻擊方式", "劫持/欺騙"))
	} else if port == 110 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "pop3"), log.String("攻擊方式", "爆破"))
	} else if port == 139 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "samba"), log.String("攻擊方式", "爆破/未授權防問/遠程代碼執行"))
	} else if port == 143 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "imap"), log.String("攻擊方式", "爆破"))
	} else if port == 161 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "snmp"), log.String("攻擊方式", "爆破"))
	} else if port == 389 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "ldap"), log.String("攻擊方式", "注入攻擊/未授權防問"))
	} else if port == 512 || port == 513 || port == 514 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "linux"), log.String("攻擊方式", "遠端登入rlogin"))
	} else if port == 873 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "rsync"), log.String("攻擊方式", "未授權防問"))
	} else if port == 1080 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "socket"), log.String("攻擊方式", "爆破/內網渗透"))
	} else if port == 1352 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "lotus"), log.String("攻擊方式", "Ibm Lotus漏洞"))
	} else if port == 1433 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "mssql"), log.String("攻擊方式", "爆破/使用系统用戶登入/注入攻擊"))
	} else if port == 1521 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "oracle"), log.String("攻擊方式", "爆破TNS/注入攻擊"))
	} else if port == 2049 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "nfs"), log.String("攻擊方式", "不當的配置"))
	} else if port == 2181 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "zookeeper"), log.String("攻擊方式", "未授權防問"))
	} else if port == 3306 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "mysql"), log.String("攻擊方式", "爆破/拒绝服務/注入"))
	} else if port == 3389 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "rdp"), log.String("攻擊方式", "爆破/Shift後門"))
	} else if port == 4848 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "glassfish"), log.String("攻擊方式", "爆破/繞過認證"))
	} else if port == 5000 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "sybase/DB2"), log.String("攻擊方式", "爆破/注入"))
	} else if port == 5432 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "postgresql"), log.String("攻擊方式", "Buffer Overflow/注入攻擊/爆破"))
	} else if port == 5632 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "pcanywhere"), log.String("攻擊方式", "拒绝服務/代碼執行"))
	} else if port == 5900 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "vnc"), log.String("攻擊方式", "爆破/繞過認證"))
	} else if port == 6379 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "redis"), log.String("攻擊方式", "未授權防問/爆破"))
	} else if port == 7001 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "weblogic"), log.String("攻擊方式", "Java反序列化/部署webshell"))
	} else if port == 80 || port == 443 || port == 8080 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "web"), log.String("攻擊方式", "常見web攻擊/爆破/對應版本漏洞"))
	} else if port == 8069 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "zabbix"), log.String("攻擊方式", "遠程代碼執行"))
	} else if port == 9090 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "websphere"), log.String("攻擊方式", "爆破/Java反序列"))
	} else if port == 9200 || port == 9300 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "elasticsearch"), log.String("攻擊方式", "遠程代碼執行"))
	} else if port == 11211 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "memcacache"), log.String("攻擊方式", "未授權防問"))
	} else if port == 27017 {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "mongodb"), log.String("攻擊方式", "爆破/未授權防問"))
	}
}
