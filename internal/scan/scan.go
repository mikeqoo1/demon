package scan

import (
	log "demon/internal/logger"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// NewScan 產生一個掃描的物件
func NewScan(ip string, ports string) *Scan {
	//初始化
	s := &Scan{
		ip:   ip,
		port: ports,
	}
	return s
}

// ParsePort 解析端口字串，支援 80 / 80,81 / 80|81 / 80-83 / 80~85 五種格式。
// 任一段無法轉成數字都回錯誤，避免把壞輸入靜靜當成 port 0 送去掃描。
func (s *Scan) ParsePort(portstr string) ([]int, error) {
	portstr = strings.TrimSpace(portstr)

	// 列舉：逗號或直線分隔
	if strings.ContainsAny(portstr, ",|") {
		var ports []int
		fields := strings.FieldsFunc(portstr, func(r rune) bool { return r == ',' || r == '|' })
		for _, v := range fields {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("無效的端口 %q", v)
			}
			ports = append(ports, n)
		}
		return ports, nil
	}

	// 區間：- 或 ~ 分隔
	if i := strings.IndexAny(portstr, "-~"); i >= 0 {
		start, err1 := strconv.Atoi(strings.TrimSpace(portstr[:i]))
		end, err2 := strconv.Atoi(strings.TrimSpace(portstr[i+1:]))
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("無效的端口區間 %q", portstr)
		}
		if start >= end {
			return nil, errors.New(fmt.Sprint("範圍區間有問題!!! ", start, "-", end))
		}
		ports := make([]int, 0, end-start+1)
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	// 單一端口
	n, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, fmt.Errorf("無效的端口 %q", portstr)
	}
	return []int{n}, nil
}

// CheckPort 檢查Port合理性
func (s *Scan) CheckPort(port int) error {
	var err error
	if port < 1 || port > 65535 {
		return errors.New("端口號範圍超出")
	}
	return err
}

// dialTimeout 是判斷單一端口開放與否的連線逾時。
// 太短會在較慢的網路上把開放端口誤判為關閉；太長會拖慢全端口掃描。
// ponytail: 固定 500ms，跨網段掃描若有誤判再往上調。
const dialTimeout = 500 * time.Millisecond

// CheckPortOpen 檢查Port是否被開啟
func (s *Scan) CheckPortOpen(ip string, port int) (bool, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), dialTimeout)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}

// DefaultScanWorkers 是全端口掃描預設的並行連線數，
// 刻意壓在系統預設 fd 上限（通常 1024）之下，留餘裕給其他連線。
const DefaultScanWorkers = 500

// ScanPorts 以最多 workers 個並行連線掃描 [from,to] 區間，回傳排序後的開放端口。
// 用有界 worker pool 取代「一次開 65535 個 goroutine」，避免耗盡檔案描述符而漏掃。
func (s *Scan) ScanPorts(ip string, from, to, workers int) []int {
	if workers < 1 {
		workers = 1
	}
	portsCh := make(chan int, workers)
	openCh := make(chan int, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portsCh {
				if open, _ := s.CheckPortOpen(ip, p); open {
					openCh <- p
				}
			}
		}()
	}
	go func() {
		for p := from; p <= to; p++ {
			portsCh <- p
		}
		close(portsCh)
	}()
	go func() {
		wg.Wait()
		close(openCh)
	}()
	var open []int
	for p := range openCh {
		open = append(open, p)
	}
	sort.Ints(open)
	return open
}

// PossibleVulnerability 紀錄漏洞
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
