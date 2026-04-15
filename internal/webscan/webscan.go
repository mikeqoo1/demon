package webscan

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

// WebFinding Web 漏洞發現
type WebFinding struct {
	Category    string // 標頭安全, SSL/TLS, 敏感路徑, HTTP方法
	Item        string
	Detail      string
	RiskLevel   string // 嚴重, 高, 中, 低, 資訊
	Suggestion  string
}

// WebScanner Web 漏洞掃描器
type WebScanner struct {
	TargetURL string
	client    *http.Client
	Findings  []WebFinding
}

// NewWebScanner 建立掃描器
func NewWebScanner(targetURL string) *WebScanner {
	// 跳過 TLS 驗證（滲透測試用途）
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
	}
	return &WebScanner{
		TargetURL: targetURL,
		client: &http.Client{
			Transport: tr,
			Timeout:   15 * time.Second,
			// 不自動跟隨重導向，方便觀察原始回應
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ScanAll 執行所有 Web 檢測
func (ws *WebScanner) ScanAll() error {
	fmt.Printf("    [*] 檢測目標: %s\n", ws.TargetURL)

	fmt.Println("    [*] HTTP 回應標頭分析...")
	ws.ScanHeaders()

	fmt.Println("    [*] SSL/TLS 憑證檢測...")
	ws.ScanTLS()

	fmt.Println("    [*] 敏感路徑探測...")
	ws.ScanSensitivePaths()

	fmt.Println("    [*] HTTP 危險方法測試...")
	ws.ScanHTTPMethods()

	return nil
}

// ScanHeaders 檢測 HTTP 回應標頭
func (ws *WebScanner) ScanHeaders() {
	resp, err := ws.client.Get(ws.TargetURL)
	if err != nil {
		ws.Findings = append(ws.Findings, WebFinding{
			Category:  "連線",
			Item:      "無法連線",
			Detail:    fmt.Sprintf("連線失敗: %s", err.Error()),
			RiskLevel: "資訊",
		})
		return
	}
	defer resp.Body.Close()

	// 記錄伺服器基本資訊
	ws.Findings = append(ws.Findings, WebFinding{
		Category:  "基本資訊",
		Item:      "HTTP 狀態碼",
		Detail:    fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		RiskLevel: "資訊",
	})

	// Server 標頭 — 版本洩漏
	server := resp.Header.Get("Server")
	if server != "" {
		risk := "中"
		detail := fmt.Sprintf("Server: %s — 洩漏伺服器版本資訊", server)
		suggestion := "移除或隱藏 Server 標頭中的版本資訊"
		// 如果包含具體版本號，風險更高
		if containsVersion(server) {
			risk = "高"
			detail = fmt.Sprintf("Server: %s — 洩漏伺服器詳細版本，攻擊者可針對特定版本搜尋已知漏洞", server)
		}
		ws.Findings = append(ws.Findings, WebFinding{
			Category:   "標頭安全",
			Item:       "Server 版本洩漏",
			Detail:     detail,
			RiskLevel:  risk,
			Suggestion: suggestion,
		})
	}

	// X-Powered-By 標頭
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		ws.Findings = append(ws.Findings, WebFinding{
			Category:   "標頭安全",
			Item:       "X-Powered-By 洩漏",
			Detail:     fmt.Sprintf("X-Powered-By: %s — 洩漏後端技術棧", poweredBy),
			RiskLevel:  "中",
			Suggestion: "移除 X-Powered-By 標頭",
		})
	}

	// X-AspNet-Version / X-AspNetMvc-Version
	aspnet := resp.Header.Get("X-AspNet-Version")
	if aspnet != "" {
		ws.Findings = append(ws.Findings, WebFinding{
			Category:   "標頭安全",
			Item:       "ASP.NET 版本洩漏",
			Detail:     fmt.Sprintf("X-AspNet-Version: %s", aspnet),
			RiskLevel:  "中",
			Suggestion: "在 web.config 中設定 enableVersionHeader=false",
		})
	}

	// 檢查缺少的安全標頭
	securityHeaders := []struct {
		Name       string
		Risk       string
		Suggestion string
	}{
		{"X-Frame-Options", "中", "設定 X-Frame-Options: DENY 或 SAMEORIGIN，防止 Clickjacking 攻擊"},
		{"X-Content-Type-Options", "中", "設定 X-Content-Type-Options: nosniff，防止 MIME type sniffing"},
		{"X-XSS-Protection", "低", "設定 X-XSS-Protection: 1; mode=block"},
		{"Strict-Transport-Security", "高", "設定 HSTS 標頭，強制使用 HTTPS 連線"},
		{"Content-Security-Policy", "中", "設定 CSP 標頭，防止 XSS 和資料注入攻擊"},
		{"Referrer-Policy", "低", "設定 Referrer-Policy，控制 Referer 資訊洩漏"},
		{"Permissions-Policy", "低", "設定 Permissions-Policy，限制瀏覽器功能存取"},
	}

	for _, h := range securityHeaders {
		if resp.Header.Get(h.Name) == "" {
			ws.Findings = append(ws.Findings, WebFinding{
				Category:   "標頭安全",
				Item:       fmt.Sprintf("缺少 %s", h.Name),
				Detail:     fmt.Sprintf("回應中缺少 %s 安全標頭", h.Name),
				RiskLevel:  h.Risk,
				Suggestion: h.Suggestion,
			})
		}
	}

	// Set-Cookie 安全性
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)
		cookieName := strings.Split(cookie, "=")[0]
		if !strings.Contains(cookieLower, "httponly") {
			ws.Findings = append(ws.Findings, WebFinding{
				Category:   "標頭安全",
				Item:       "Cookie 缺少 HttpOnly",
				Detail:     fmt.Sprintf("Cookie '%s' 未設定 HttpOnly，可被 JavaScript 存取", cookieName),
				RiskLevel:  "高",
				Suggestion: "所有 Cookie 設定 HttpOnly 標記",
			})
		}
		if !strings.Contains(cookieLower, "secure") {
			ws.Findings = append(ws.Findings, WebFinding{
				Category:   "標頭安全",
				Item:       "Cookie 缺少 Secure",
				Detail:     fmt.Sprintf("Cookie '%s' 未設定 Secure，可能透過 HTTP 明文傳送", cookieName),
				RiskLevel:  "中",
				Suggestion: "所有 Cookie 設定 Secure 標記",
			})
		}
	}
}

// ScanTLS 檢測 SSL/TLS 安全性
func (ws *WebScanner) ScanTLS() {
	if !strings.HasPrefix(ws.TargetURL, "https://") {
		ws.Findings = append(ws.Findings, WebFinding{
			Category:   "SSL/TLS",
			Item:       "未使用 HTTPS",
			Detail:     "網站未使用 HTTPS 加密連線，所有資料以明文傳輸",
			RiskLevel:  "嚴重",
			Suggestion: "啟用 HTTPS 並設定自動跳轉",
		})
		return
	}

	host := extractHost(ws.TargetURL)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		ws.Findings = append(ws.Findings, WebFinding{
			Category:  "SSL/TLS",
			Item:      "TLS 連線失敗",
			Detail:    fmt.Sprintf("無法建立 TLS 連線: %s", err.Error()),
			RiskLevel: "高",
		})
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// TLS 版本
	tlsVersion := tlsVersionName(state.Version)
	ws.Findings = append(ws.Findings, WebFinding{
		Category:  "SSL/TLS",
		Item:      "TLS 版本",
		Detail:    fmt.Sprintf("使用 %s", tlsVersion),
		RiskLevel: "資訊",
	})

	if state.Version < tls.VersionTLS12 {
		ws.Findings = append(ws.Findings, WebFinding{
			Category:   "SSL/TLS",
			Item:       "TLS 版本過低",
			Detail:     fmt.Sprintf("使用 %s，存在已知安全漏洞", tlsVersion),
			RiskLevel:  "嚴重",
			Suggestion: "升級至 TLS 1.2 或 TLS 1.3",
		})
	}

	// 憑證資訊
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		ws.Findings = append(ws.Findings, WebFinding{
			Category:  "SSL/TLS",
			Item:      "憑證主體",
			Detail:    fmt.Sprintf("CN=%s, 發行者=%s", cert.Subject.CommonName, cert.Issuer.CommonName),
			RiskLevel: "資訊",
		})

		ws.Findings = append(ws.Findings, WebFinding{
			Category:  "SSL/TLS",
			Item:      "憑證有效期",
			Detail:    fmt.Sprintf("%s ~ %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")),
			RiskLevel: "資訊",
		})

		// 憑證過期檢查
		now := time.Now()
		if now.After(cert.NotAfter) {
			ws.Findings = append(ws.Findings, WebFinding{
				Category:   "SSL/TLS",
				Item:       "憑證已過期",
				Detail:     fmt.Sprintf("憑證於 %s 過期", cert.NotAfter.Format("2006-01-02")),
				RiskLevel:  "嚴重",
				Suggestion: "立即更新 SSL 憑證",
			})
		} else if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
			ws.Findings = append(ws.Findings, WebFinding{
				Category:   "SSL/TLS",
				Item:       "憑證即將過期",
				Detail:     fmt.Sprintf("憑證將於 %s 過期（不到 30 天）", cert.NotAfter.Format("2006-01-02")),
				RiskLevel:  "高",
				Suggestion: "儘快更新 SSL 憑證",
			})
		}

		// 自簽憑證
		if cert.Issuer.CommonName == cert.Subject.CommonName {
			ws.Findings = append(ws.Findings, WebFinding{
				Category:   "SSL/TLS",
				Item:       "自簽憑證",
				Detail:     "使用自簽憑證，瀏覽器會顯示不安全警告",
				RiskLevel:  "中",
				Suggestion: "使用受信任的 CA 簽發的憑證",
			})
		}
	}
}

// ScanSensitivePaths 探測常見敏感路徑
func (ws *WebScanner) ScanSensitivePaths() {
	paths := []struct {
		Path        string
		Description string
		Risk        string
	}{
		// 管理後台
		{"/admin", "管理後台", "高"},
		{"/admin/", "管理後台", "高"},
		{"/administrator", "管理後台", "高"},
		{"/manager", "管理後台", "高"},
		{"/wp-admin", "WordPress 管理後台", "高"},
		{"/wp-login.php", "WordPress 登入頁", "高"},
		{"/phpmyadmin", "phpMyAdmin 資料庫管理", "嚴重"},
		{"/phpmyadmin/", "phpMyAdmin 資料庫管理", "嚴重"},

		// 設定檔與敏感檔案
		{"/robots.txt", "robots.txt 路徑洩漏", "低"},
		{"/.env", "環境變數檔", "嚴重"},
		{"/config.php", "PHP 設定檔", "嚴重"},
		{"/web.config", "IIS 設定檔", "嚴重"},
		{"/.git/HEAD", "Git 版本庫洩漏", "嚴重"},
		{"/.svn/entries", "SVN 版本庫洩漏", "嚴重"},
		{"/.DS_Store", "macOS 目錄檔案洩漏", "中"},
		{"/crossdomain.xml", "Flash 跨域設定", "中"},
		{"/sitemap.xml", "Sitemap 網站地圖", "低"},
		{"/server-status", "Apache 伺服器狀態", "高"},
		{"/server-info", "Apache 伺服器資訊", "高"},

		// 備份檔案
		{"/backup.sql", "SQL 備份檔", "嚴重"},
		{"/backup.zip", "備份壓縮檔", "嚴重"},
		{"/backup.tar.gz", "備份壓縮檔", "嚴重"},
		{"/db.sql", "資料庫備份", "嚴重"},
		{"/dump.sql", "資料庫備份", "嚴重"},

		// API 文件
		{"/swagger-ui.html", "Swagger API 文件", "中"},
		{"/api-docs", "API 文件", "中"},
		{"/swagger.json", "Swagger JSON", "中"},

		// 錯誤/除錯頁面
		{"/elmah.axd", "ASP.NET 錯誤日誌", "高"},
		{"/trace.axd", "ASP.NET Trace", "高"},
		{"/info.php", "PHP 資訊頁面", "高"},
		{"/phpinfo.php", "PHP 資訊頁面", "高"},
		{"/test.php", "測試頁面", "中"},
	}

	baseURL := strings.TrimRight(ws.TargetURL, "/")
	// 去掉 hash fragment (SPA 路由)
	if idx := strings.Index(baseURL, "#"); idx != -1 {
		baseURL = strings.TrimRight(baseURL[:idx], "/")
	}

	// 取得首頁 body 作為 SPA 誤報比對基準
	baseResp, err := ws.client.Get(baseURL + "/")
	var baseBody string
	if err == nil {
		bodyBytes, _ := ioutil.ReadAll(baseResp.Body)
		baseResp.Body.Close()
		baseBody = string(bodyBytes)
	}

	// SPA 偵測: 用多個不存在路徑測試，如果都回 200 且 body 相近就是 SPA
	isSPA := false
	fakeURLs := []string{
		baseURL + "/zz_not_exist_a1b2c3",
		baseURL + "/xx_fake_path_9f8e7d",
	}
	spaMatchCount := 0
	for _, fakeURL := range fakeURLs {
		nfResp, err := ws.client.Get(fakeURL)
		if err != nil {
			continue
		}
		nfBody, _ := ioutil.ReadAll(nfResp.Body)
		nfResp.Body.Close()
		if nfResp.StatusCode == 200 && len(baseBody) > 0 && bodySimilar(baseBody, string(nfBody)) {
			spaMatchCount++
		}
	}
	if spaMatchCount >= 2 {
		isSPA = true
		fmt.Println("      偵測到 SPA 架構，啟用誤報過濾...")
	}

	// 非 HTML 檔案的預期 Content-Type（用於排除 SPA 誤報）
	nonHTMLExtensions := map[string]bool{
		".sql": true, ".zip": true, ".gz": true, ".env": true,
		".php": true, ".config": true, ".xml": true, ".json": true,
		".axd": true, ".txt": true,
	}

	found := 0

	for _, p := range paths {
		testURL := baseURL + p.Path
		resp, err := ws.client.Get(testURL)
		if err != nil {
			continue
		}
		respBody, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			// 誤報過濾 1: SPA body 比對
			if isSPA && resp.StatusCode == 200 && bodySimilar(baseBody, string(respBody)) {
				continue
			}

			// 誤報過濾 2: Content-Type 檢查
			// 如果請求的是 .sql/.zip/.env 等檔案，但回傳 text/html，幾乎確定是假的
			contentType := resp.Header.Get("Content-Type")
			isHTMLResponse := strings.Contains(contentType, "text/html")
			if resp.StatusCode == 200 && isHTMLResponse {
				isNonHTML := false
				for ext := range nonHTMLExtensions {
					if strings.HasSuffix(p.Path, ext) {
						isNonHTML = true
						break
					}
				}
				// 也檢查 . 開頭的隱藏檔 (.env, .git, .svn, .DS_Store)
				pathBase := p.Path[strings.LastIndex(p.Path, "/")+1:]
				if strings.HasPrefix(pathBase, ".") {
					isNonHTML = true
				}
				if isNonHTML {
					continue // HTML 回應 ≠ 真實檔案，過濾
				}
			}

			// 誤報過濾 3: 如果回應 body 跟首頁一模一樣 (即使 SPA 偵測沒觸發)
			if resp.StatusCode == 200 && len(baseBody) > 0 && bodySimilar(baseBody, string(respBody)) {
				continue
			}

			status := "可存取 (200)"
			risk := p.Risk
			if resp.StatusCode == 403 {
				status = "存在但被禁止 (403)"
				risk = "低"
			}
			ws.Findings = append(ws.Findings, WebFinding{
				Category:   "敏感路徑",
				Item:       p.Description,
				Detail:     fmt.Sprintf("%s — %s", p.Path, status),
				RiskLevel:  risk,
				Suggestion: fmt.Sprintf("確認 %s 是否應該對外開放，建議限制存取或移除", p.Path),
			})
			found++
			fmt.Printf("      發現: %-30s [%d] %s\n", p.Path, resp.StatusCode, p.Description)
		}
	}

	if found == 0 {
		fmt.Println("      未發現常見敏感路徑")
	}
}

// bodySimilar 比對兩個 body 是否相似 (用於過濾 SPA 誤報)
func bodySimilar(a, b string) bool {
	if a == b {
		return true
	}
	lenA, lenB := len(a), len(b)
	if lenA == 0 || lenB == 0 {
		return false
	}
	diff := lenA - lenB
	if diff < 0 {
		diff = -diff
	}
	// 長度差異在 5% 以內視為相同 (SPA 可能有微小差異)
	return float64(diff)/float64(lenA) < 0.05
}

// ScanHTTPMethods 測試 HTTP 危險方法
func (ws *WebScanner) ScanHTTPMethods() {
	// 先取 GET 基準回應，用於比對 SPA 誤報
	baseResp, err := ws.client.Get(ws.TargetURL)
	var baseBody string
	if err == nil {
		bodyBytes, _ := ioutil.ReadAll(baseResp.Body)
		baseResp.Body.Close()
		baseBody = string(bodyBytes)
	}

	dangerousMethods := []struct {
		Method string
		Risk   string
		Desc   string
	}{
		{"PUT", "高", "可能允許上傳任意檔案"},
		{"DELETE", "高", "可能允許刪除伺服器檔案"},
		{"TRACE", "中", "可能導致 XST (Cross-Site Tracing) 攻擊"},
		{"OPTIONS", "低", "洩漏伺服器支援的 HTTP 方法"},
	}

	for _, m := range dangerousMethods {
		req, err := http.NewRequest(m.Method, ws.TargetURL, nil)
		if err != nil {
			continue
		}
		resp, err := ws.client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		// 如果不是 405 (Method Not Allowed)，代表伺服器可能接受此方法
		if resp.StatusCode != 405 && resp.StatusCode != 501 {
			// SPA 誤報過濾: 如果 PUT/DELETE 回應跟 GET 一模一樣，
			// 那其實只是 SPA 不管什麼方法都回 index.html
			if m.Method != "OPTIONS" && resp.StatusCode == 200 &&
				len(baseBody) > 0 && bodySimilar(baseBody, string(respBody)) {
				continue
			}

			risk := m.Risk
			if m.Method == "OPTIONS" && resp.StatusCode == 200 {
				allow := resp.Header.Get("Allow")
				if allow != "" {
					ws.Findings = append(ws.Findings, WebFinding{
						Category:   "HTTP 方法",
						Item:       "OPTIONS 回應",
						Detail:     fmt.Sprintf("伺服器允許的方法: %s", allow),
						RiskLevel:  "資訊",
						Suggestion: "停用不需要的 HTTP 方法",
					})
				}
				risk = "資訊"
			}

			if m.Method != "OPTIONS" {
				ws.Findings = append(ws.Findings, WebFinding{
					Category:   "HTTP 方法",
					Item:       fmt.Sprintf("%s 方法已啟用", m.Method),
					Detail:     fmt.Sprintf("伺服器接受 %s 請求 (回應 %d) — %s", m.Method, resp.StatusCode, m.Desc),
					RiskLevel:  risk,
					Suggestion: fmt.Sprintf("停用 %s 方法", m.Method),
				})
				fmt.Printf("      警告: %s 方法已啟用 [%d]\n", m.Method, resp.StatusCode)
			}
		}
	}
}

// === 輔助函式 ===

func extractHost(url string) string {
	host := url
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]
	return host
}

func containsVersion(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("未知 (0x%04x)", v)
	}
}
