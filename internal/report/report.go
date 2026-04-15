package report

import (
	"demon/internal/scan"
	"demon/internal/webscan"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Step 測試步驟紀錄
type Step struct {
	Index  int
	Time   time.Time
	Action string
	Result string
}

// ExploitResult 攻擊嘗試結果
type ExploitResult struct {
	Method   string
	Target   string
	Success  bool
	Detail   string
	Username string
	Password string
}

// Report 滲透測試報告
type Report struct {
	Target      string
	Tester      string
	StartTime   time.Time
	EndTime     time.Time
	OpenPorts   []int
	Vulns       []scan.VulnInfo
	Exploits    []ExploitResult
	WebFindings []webscan.WebFinding
	Steps       []Step
	stepCount   int
}

// NewReport 建立新報告
func NewReport(target, tester string) *Report {
	return &Report{
		Target:    target,
		Tester:    tester,
		StartTime: time.Now(),
	}
}

// AddStep 新增測試步驟
func (r *Report) AddStep(action, result string) {
	r.stepCount++
	r.Steps = append(r.Steps, Step{
		Index:  r.stepCount,
		Time:   time.Now(),
		Action: action,
		Result: result,
	})
}

// AddOpenPort 新增開放端口
func (r *Report) AddOpenPort(port int) {
	r.OpenPorts = append(r.OpenPorts, port)
}

// AddVuln 新增漏洞發現
func (r *Report) AddVuln(v scan.VulnInfo) {
	r.Vulns = append(r.Vulns, v)
}

// AddExploit 新增攻擊結果
func (r *Report) AddExploit(e ExploitResult) {
	r.Exploits = append(r.Exploits, e)
}

// AddWebFindings 新增 Web 漏洞發現
func (r *Report) AddWebFindings(findings []webscan.WebFinding) {
	r.WebFindings = append(r.WebFindings, findings...)
}

// Generate 產出 Markdown 格式的滲透測試報告
func (r *Report) Generate(outputPath string) error {
	r.EndTime = time.Now()
	sort.Ints(r.OpenPorts)

	var sb strings.Builder
	const timeFmt = "2006-01-02 15:04:05"

	// === 標題 ===
	sb.WriteString("# 滲透測試報告\n\n")

	// === 基本資訊 ===
	sb.WriteString("## 1. 基本資訊\n\n")
	sb.WriteString(fmt.Sprintf("| 項目 | 內容 |\n"))
	sb.WriteString(fmt.Sprintf("| --- | --- |\n"))
	sb.WriteString(fmt.Sprintf("| 目標 IP | %s |\n", r.Target))
	sb.WriteString(fmt.Sprintf("| 測試人員 | %s |\n", r.Tester))
	sb.WriteString(fmt.Sprintf("| 開始時間 | %s |\n", r.StartTime.Format(timeFmt)))
	sb.WriteString(fmt.Sprintf("| 結束時間 | %s |\n", r.EndTime.Format(timeFmt)))
	sb.WriteString(fmt.Sprintf("| 測試耗時 | %s |\n", r.EndTime.Sub(r.StartTime).Round(time.Second)))
	sb.WriteString("\n")

	// === 摘要 ===
	sb.WriteString("## 2. 測試摘要\n\n")
	criticalCount, highCount, mediumCount, lowCount := r.countRiskLevels()
	successCount := 0
	for _, e := range r.Exploits {
		if e.Success {
			successCount++
		}
	}
	totalVulns := len(r.Vulns) + len(r.WebFindings)
	sb.WriteString(fmt.Sprintf("- 開放端口數量: **%d**\n", len(r.OpenPorts)))
	sb.WriteString(fmt.Sprintf("- 發現漏洞數量: **%d** (嚴重:%d / 高:%d / 中:%d / 低:%d)\n",
		totalVulns, criticalCount, highCount, mediumCount, lowCount))
	if len(r.WebFindings) > 0 {
		sb.WriteString(fmt.Sprintf("- Web 檢測項目: **%d**\n", len(r.WebFindings)))
	}
	sb.WriteString(fmt.Sprintf("- 攻擊嘗試次數: **%d**\n", len(r.Exploits)))
	sb.WriteString(fmt.Sprintf("- 攻擊成功次數: **%d**\n", successCount))
	if successCount > 0 {
		sb.WriteString("\n> **警告: 存在可被利用的漏洞，請立即修復！**\n")
	}
	sb.WriteString("\n")

	// === 測試步驟 ===
	sb.WriteString("## 3. 測試步驟\n\n")
	for _, step := range r.Steps {
		sb.WriteString(fmt.Sprintf("### 步驟 %d: %s\n\n", step.Index, step.Action))
		sb.WriteString(fmt.Sprintf("- 時間: %s\n", step.Time.Format(timeFmt)))
		sb.WriteString(fmt.Sprintf("- 結果: %s\n\n", step.Result))
	}

	// === 開放端口 ===
	sb.WriteString("## 4. 開放端口清單\n\n")
	if len(r.OpenPorts) > 0 {
		sb.WriteString("| Port | 服務 | 建議攻擊方式 | 風險等級 |\n")
		sb.WriteString("| --- | --- | --- | --- |\n")
		for _, v := range r.Vulns {
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n",
				v.Port, v.Service, v.AttackMethod, v.RiskLevel))
		}
	} else {
		sb.WriteString("未發現開放端口\n")
	}
	sb.WriteString("\n")

	// === Web 漏洞 ===
	if len(r.WebFindings) > 0 {
		sb.WriteString("## 5. Web 應用程式檢測結果\n\n")

		// 按 Category 分組
		categories := []string{"基本資訊", "標頭安全", "SSL/TLS", "敏感路徑", "HTTP 方法", "SQL Injection", "連線"}
		for _, cat := range categories {
			var items []webscan.WebFinding
			for _, f := range r.WebFindings {
				if f.Category == cat {
					items = append(items, f)
				}
			}
			if len(items) == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf("### %s\n\n", cat))
			sb.WriteString("| 項目 | 說明 | 風險等級 | 修復建議 |\n")
			sb.WriteString("| --- | --- | --- | --- |\n")
			for _, f := range items {
				suggestion := f.Suggestion
				if suggestion == "" {
					suggestion = "-"
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					f.Item, f.Detail, f.RiskLevel, suggestion))
			}
			sb.WriteString("\n")
		}
	}

	// === 攻擊結果 ===
	sectionNum := 5
	if len(r.WebFindings) > 0 {
		sectionNum = 6
	}
	if len(r.Exploits) > 0 {
		sb.WriteString(fmt.Sprintf("## %d. 攻擊嘗試結果\n\n", sectionNum))
		for i, e := range r.Exploits {
			status := "失敗"
			if e.Success {
				status = "成功"
			}
			sb.WriteString(fmt.Sprintf("### 攻擊 %d: %s\n\n", i+1, e.Method))
			sb.WriteString(fmt.Sprintf("- 目標: %s\n", e.Target))
			sb.WriteString(fmt.Sprintf("- 狀態: **%s**\n", status))
			if e.Success && e.Username != "" {
				sb.WriteString(fmt.Sprintf("- 取得帳號: `%s`\n", e.Username))
				sb.WriteString(fmt.Sprintf("- 取得密碼: `%s`\n", e.Password))
			}
			sb.WriteString(fmt.Sprintf("- 說明: %s\n\n", e.Detail))
		}
	}

	// === 風險評估 ===
	riskSectionNum := sectionNum + 1
	if len(r.Exploits) == 0 {
		riskSectionNum = sectionNum
	}
	sb.WriteString(fmt.Sprintf("## %d. 風險評估\n\n", riskSectionNum))
	overallRisk := r.getOverallRisk(criticalCount, highCount, successCount)
	sb.WriteString(fmt.Sprintf("**整體風險等級: %s**\n\n", overallRisk))
	if criticalCount > 0 {
		sb.WriteString(fmt.Sprintf("- 嚴重風險項目 %d 個，建議立即處理\n", criticalCount))
	}
	if highCount > 0 {
		sb.WriteString(fmt.Sprintf("- 高風險項目 %d 個，建議盡快處理\n", highCount))
	}
	if successCount > 0 {
		sb.WriteString("- 已確認存在可被利用的漏洞，攻擊者可取得系統存取權限\n")
	}
	sb.WriteString("\n")

	// === 修復建議 ===
	sb.WriteString(fmt.Sprintf("## %d. 修復建議\n\n", riskSectionNum+1))
	suggestions := r.generateSuggestions()
	for i, s := range suggestions {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, s))
	}
	sb.WriteString("\n")

	// === 結尾 ===
	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("報告產出時間: %s\n", time.Now().Format(timeFmt)))
	sb.WriteString(fmt.Sprintf("報告產出工具: demon 滲透測試框架\n"))

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

func (r *Report) countRiskLevels() (critical, high, medium, low int) {
	for _, v := range r.Vulns {
		switch v.RiskLevel {
		case "嚴重":
			critical++
		case "高":
			high++
		case "中":
			medium++
		case "低":
			low++
		}
	}
	for _, f := range r.WebFindings {
		switch f.RiskLevel {
		case "嚴重":
			critical++
		case "高":
			high++
		case "中":
			medium++
		case "低":
			low++
		}
	}
	return
}

func (r *Report) getOverallRisk(criticalCount, highCount, successCount int) string {
	if successCount > 0 || criticalCount > 0 {
		return "嚴重 (Critical)"
	}
	if highCount > 0 {
		return "高 (High)"
	}
	if len(r.Vulns) > 0 {
		return "中 (Medium)"
	}
	return "低 (Low)"
}

func (r *Report) generateSuggestions() []string {
	var suggestions []string
	seen := make(map[string]bool)

	for _, v := range r.Vulns {
		switch v.Service {
		case "ssh":
			add(&suggestions, seen, "SSH: 停用密碼登入，改用金鑰認證；限制來源 IP；更換非標準端口")
		case "telnet":
			add(&suggestions, seen, "Telnet: 停用 Telnet 服務，改用 SSH")
		case "ftp/sftp文件傳輸協議":
			add(&suggestions, seen, "FTP: 停用匿名登入；改用 SFTP；限制存取目錄")
		case "mysql":
			add(&suggestions, seen, "MySQL: 禁止遠端 root 登入；設定強密碼；限制來源 IP")
		case "redis":
			add(&suggestions, seen, "Redis: 設定密碼認證；禁止外網存取；停用危險指令")
		case "mongodb":
			add(&suggestions, seen, "MongoDB: 啟用認證機制；禁止外網存取；停用 REST API")
		case "rdp":
			add(&suggestions, seen, "RDP: 啟用 NLA 認證；限制來源 IP；設定帳號鎖定策略")
		case "elasticsearch":
			add(&suggestions, seen, "Elasticsearch: 啟用 X-Pack 安全模組；禁止外網存取")
		case "weblogic":
			add(&suggestions, seen, "WebLogic: 更新至最新版本；移除預設應用；限制管理介面存取")
		case "web":
			add(&suggestions, seen, "Web: 進行完整的 Web 應用程式弱點掃描 (OWASP Top 10)")
		case "ldap":
			add(&suggestions, seen, "LDAP: 啟用 LDAPS 加密；設定存取控制清單")
		case "vnc":
			add(&suggestions, seen, "VNC: 設定強密碼；使用 SSH Tunnel 加密連線")
		case "samba":
			add(&suggestions, seen, "Samba: 更新至最新版本；停用不需要的共享；限制存取權限")
		}
	}

	for _, e := range r.Exploits {
		if e.Success && strings.Contains(e.Method, "SSH") {
			add(&suggestions, seen, "緊急: SSH 帳號密碼已被破解，請立即更換密碼並啟用金鑰認證")
		}
	}

	// Web 漏洞建議
	for _, f := range r.WebFindings {
		if f.Suggestion != "" && (f.RiskLevel == "嚴重" || f.RiskLevel == "高") {
			add(&suggestions, seen, f.Suggestion)
		}
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "持續進行定期資安檢測")
	}

	suggestions = append(suggestions, "關閉不必要的服務與端口")
	suggestions = append(suggestions, "部署防火牆規則，限制存取來源")
	suggestions = append(suggestions, "建立定期弱點掃描與修補機制")

	return suggestions
}

func add(suggestions *[]string, seen map[string]bool, s string) {
	if !seen[s] {
		seen[s] = true
		*suggestions = append(*suggestions, s)
	}
}
