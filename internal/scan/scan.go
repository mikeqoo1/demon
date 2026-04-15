package scan

import (
	db "demon/internal/dblib"
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

// VulnInfo 漏洞資訊結構
type VulnInfo struct {
	Port         int
	Service      string
	AttackMethod string
	RiskLevel    string // 嚴重, 高, 中, 低
}

// GetVulnerabilityInfo 回傳結構化的漏洞資訊
func (s *Scan) GetVulnerabilityInfo(port int) VulnInfo {
	info := VulnInfo{Port: port}
	switch port {
	case 21, 69:
		info.Service = "ftp/sftp文件傳輸協議"
		info.AttackMethod = "爆破/監聽/Buffer Overflow/後門"
		info.RiskLevel = "高"
	case 22:
		info.Service = "ssh"
		info.AttackMethod = "爆破OpenSSH/內網代理轉發/文件傳輸"
		info.RiskLevel = "高"
	case 23:
		info.Service = "telnet"
		info.AttackMethod = "爆破/監聽"
		info.RiskLevel = "嚴重"
	case 25:
		info.Service = "smtp郵件服務"
		info.AttackMethod = "郵件偽造"
		info.RiskLevel = "中"
	case 53:
		info.Service = "DNS域名系統"
		info.AttackMethod = "DNS區域傳輸/DNS劫持/DNS污染/DNS欺騙/利用DNS隧道技術刺透防火牆"
		info.RiskLevel = "高"
	case 67, 68:
		info.Service = "dhcp"
		info.AttackMethod = "劫持/欺騙"
		info.RiskLevel = "中"
	case 110:
		info.Service = "pop3"
		info.AttackMethod = "爆破"
		info.RiskLevel = "中"
	case 139:
		info.Service = "samba"
		info.AttackMethod = "爆破/未授權存取/遠程代碼執行"
		info.RiskLevel = "嚴重"
	case 143:
		info.Service = "imap"
		info.AttackMethod = "爆破"
		info.RiskLevel = "中"
	case 161:
		info.Service = "snmp"
		info.AttackMethod = "爆破"
		info.RiskLevel = "中"
	case 389:
		info.Service = "ldap"
		info.AttackMethod = "注入攻擊/未授權存取"
		info.RiskLevel = "高"
	case 512, 513, 514:
		info.Service = "linux rlogin"
		info.AttackMethod = "遠端登入rlogin"
		info.RiskLevel = "嚴重"
	case 873:
		info.Service = "rsync"
		info.AttackMethod = "未授權存取"
		info.RiskLevel = "高"
	case 1080:
		info.Service = "socket"
		info.AttackMethod = "爆破/內網滲透"
		info.RiskLevel = "中"
	case 1352:
		info.Service = "lotus"
		info.AttackMethod = "IBM Lotus漏洞"
		info.RiskLevel = "中"
	case 1433:
		info.Service = "mssql"
		info.AttackMethod = "爆破/使用系統用戶登入/注入攻擊"
		info.RiskLevel = "高"
	case 1521:
		info.Service = "oracle"
		info.AttackMethod = "爆破TNS/注入攻擊"
		info.RiskLevel = "高"
	case 2049:
		info.Service = "nfs"
		info.AttackMethod = "不當的配置"
		info.RiskLevel = "中"
	case 2181:
		info.Service = "zookeeper"
		info.AttackMethod = "未授權存取"
		info.RiskLevel = "高"
	case 3306:
		info.Service = "mysql"
		info.AttackMethod = "爆破/拒絕服務/注入"
		info.RiskLevel = "高"
	case 3389:
		info.Service = "rdp"
		info.AttackMethod = "爆破/Shift後門"
		info.RiskLevel = "嚴重"
	case 4848:
		info.Service = "glassfish"
		info.AttackMethod = "爆破/繞過認證"
		info.RiskLevel = "中"
	case 5000:
		info.Service = "sybase/DB2"
		info.AttackMethod = "爆破/注入"
		info.RiskLevel = "高"
	case 5432:
		info.Service = "postgresql"
		info.AttackMethod = "Buffer Overflow/注入攻擊/爆破"
		info.RiskLevel = "高"
	case 5632:
		info.Service = "pcanywhere"
		info.AttackMethod = "拒絕服務/代碼執行"
		info.RiskLevel = "高"
	case 5900:
		info.Service = "vnc"
		info.AttackMethod = "爆破/繞過認證"
		info.RiskLevel = "高"
	case 6379:
		info.Service = "redis"
		info.AttackMethod = "未授權存取/爆破"
		info.RiskLevel = "嚴重"
	case 7001:
		info.Service = "weblogic"
		info.AttackMethod = "Java反序列化/部署webshell"
		info.RiskLevel = "嚴重"
	case 80, 443, 8080:
		info.Service = "web"
		info.AttackMethod = "常見web攻擊/爆破/對應版本漏洞"
		info.RiskLevel = "中"
	case 8069:
		info.Service = "zabbix"
		info.AttackMethod = "遠程代碼執行"
		info.RiskLevel = "嚴重"
	case 9090:
		info.Service = "websphere"
		info.AttackMethod = "爆破/Java反序列化"
		info.RiskLevel = "高"
	case 9200, 9300:
		info.Service = "elasticsearch"
		info.AttackMethod = "遠程代碼執行"
		info.RiskLevel = "嚴重"
	case 11211:
		info.Service = "memcached"
		info.AttackMethod = "未授權存取"
		info.RiskLevel = "高"
	case 27017:
		info.Service = "mongodb"
		info.AttackMethod = "爆破/未授權存取"
		info.RiskLevel = "嚴重"
	default:
		info.Service = "未知的服務"
		info.AttackMethod = "未知的攻擊手段"
		info.RiskLevel = "低"
	}
	return info
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
		number, err = strconv.Atoi(portstr)
		if err != nil {
			fmt.Println("不在分隔符號內或是轉換數字錯誤:[" + portstr + "]")
			return ports, err
		} else {
			ports = append(ports, number)
		}
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

func (s *Scan) AllPortScan(ip string, port int, results chan int) {
	network := "tcp"
	portstr := strconv.Itoa(port)
	address := ip + ":" + portstr
	var timeout time.Duration = 500 * time.Millisecond
try:
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") || strings.Contains(err.Error(), "time out") {
			time.Sleep(timeout)
			goto try
		} else {
			//fmt.Println(port, "closed")
			results <- 0
			return
		}
	}

	//fmt.Printf("Port %d is open\n", port)
	conn.Close()
	results <- port
}

//PossibleVulnerability 紀錄漏洞
func (s *Scan) PossibleVulnerability(port int, logger *log.Logger) {
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
	} else {
		logger.Warn("建議攻擊方式", log.String("服務名稱", "未知的服務"), log.String("攻擊方式", "未知的攻擊手段"))
	}
}

func sql(ip string) {
	mydb := db.NewMysql(ip)
	var connectionString string
	mydb.User = "root"
	mydb.Passwd = "1234"
	mydb.Ip = ip
	mydb.Port = 3306
	mydb.Database = "mysql"
	//<username>:<pw>@tcp(<HOST>:<port>)/<dbname>"
	connectionString = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?allowNativePasswords=true", mydb.User, mydb.Passwd, mydb.Ip, mydb.Port, mydb.Database)
	err := mydb.DBOpen(connectionString)
	if err != nil {
		fmt.Println(err.Error())
	}
	err = mydb.Ping() //如果想立即驗證連線 需要用Ping()方法
	if err != nil {
		fmt.Println(err.Error())
	}
	//假設連成功紀錄帳密
	fmt.Println("成功的帳號:", mydb.User, "成功的密碼:", mydb.Passwd)
	defer mydb.Close()
}
