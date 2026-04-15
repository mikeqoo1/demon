package webscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// APIEndpoint API 登入端點資訊
type APIEndpoint struct {
	URL            string
	Method         string
	UsernameField  string
	PasswordField  string
	ContentType    string // "json" or "form"
	StatusCode     int    // 正常回應的 status code
}

// APIBruter API 登入爆破器 (針對 SPA)
type APIBruter struct {
	BaseURL   string
	Endpoint  *APIEndpoint
	client    *http.Client
	baseResp  string // 登入失敗時的回應 (基準)
	Results   []BruteResult
	mu        sync.Mutex
}

// 常見 API 登入路徑
var apiLoginPaths = []struct {
	Path          string
	UserField     string
	PassField     string
}{
	{"/api/login", "username", "password"},
	{"/api/auth/login", "username", "password"},
	{"/api/v1/login", "username", "password"},
	{"/api/v1/auth/login", "username", "password"},
	{"/api/v2/login", "username", "password"},
	{"/api/user/login", "username", "password"},
	{"/api/users/login", "username", "password"},
	{"/api/account/login", "username", "password"},
	{"/api/session", "username", "password"},
	{"/api/sessions", "username", "password"},
	{"/api/authenticate", "username", "password"},
	{"/api/token", "username", "password"},
	{"/auth/login", "username", "password"},
	{"/auth/signin", "username", "password"},
	{"/login", "username", "password"},
	{"/signin", "username", "password"},
	{"/user/login", "username", "password"},
	{"/account/login", "username", "password"},
	{"/oauth/token", "username", "password"},
	// 常見中文系統
	{"/api/Login", "UserID", "Password"},
	{"/api/Login", "userId", "password"},
	{"/api/Login", "account", "password"},
	{"/api/Member/Login", "account", "password"},
	{"/api/Auth", "username", "password"},
	{"/Home/Login", "username", "password"},
	{"/Account/Login", "username", "password"},
}

// NewAPIBruter 建立 API 爆破器
func NewAPIBruter(baseURL string) *APIBruter {
	// 去掉 hash fragment
	if idx := strings.Index(baseURL, "#"); idx != -1 {
		baseURL = strings.TrimRight(baseURL[:idx], "/")
	}
	baseURL = strings.TrimRight(baseURL, "/")

	jar, _ := cookiejar.New(nil)
	return &APIBruter{
		BaseURL: baseURL,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// DetectAPIEndpoint 自動偵測 API 登入端點
func (ab *APIBruter) DetectAPIEndpoint() (*APIEndpoint, error) {
	fmt.Println("      探測 API 登入端點...")

	for _, path := range apiLoginPaths {
		url := ab.BaseURL + path.Path

		// 嘗試 JSON POST
		endpoint := ab.tryJSONLogin(url, path.UserField, path.PassField)
		if endpoint != nil {
			ab.Endpoint = endpoint
			fmt.Printf("      找到 API 端點: %s (JSON)\n", url)
			fmt.Printf("      帳號欄位: %s, 密碼欄位: %s\n", endpoint.UsernameField, endpoint.PasswordField)
			return endpoint, nil
		}

		// 嘗試 Form POST
		endpoint = ab.tryFormLogin(url, path.UserField, path.PassField)
		if endpoint != nil {
			ab.Endpoint = endpoint
			fmt.Printf("      找到 API 端點: %s (Form)\n", url)
			fmt.Printf("      帳號欄位: %s, 密碼欄位: %s\n", endpoint.UsernameField, endpoint.PasswordField)
			return endpoint, nil
		}
	}

	return nil, fmt.Errorf("未偵測到 API 登入端點")
}

// tryJSONLogin 嘗試 JSON 格式登入
func (ab *APIBruter) tryJSONLogin(url, userField, passField string) *APIEndpoint {
	payload := map[string]string{
		userField: "test_detect_user",
		passField: "test_detect_pass",
	}
	jsonBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := ab.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	body := string(bodyBytes)

	// 判斷是否為有效的 API 端點:
	// - 回傳 JSON 格式 (不是 HTML)
	// - 狀態碼為 200, 400, 401, 403 (都代表端點存在)
	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "json")
	isValidStatus := resp.StatusCode == 200 || resp.StatusCode == 400 ||
		resp.StatusCode == 401 || resp.StatusCode == 403

	if isJSON && isValidStatus {
		ab.baseResp = body
		return &APIEndpoint{
			URL:           url,
			Method:        "POST",
			UsernameField: userField,
			PasswordField: passField,
			ContentType:   "json",
			StatusCode:    resp.StatusCode,
		}
	}

	// 即使不是 JSON，如果回傳 401 也代表端點存在
	if resp.StatusCode == 401 {
		ab.baseResp = body
		return &APIEndpoint{
			URL:           url,
			Method:        "POST",
			UsernameField: userField,
			PasswordField: passField,
			ContentType:   "json",
			StatusCode:    resp.StatusCode,
		}
	}

	return nil
}

// tryFormLogin 嘗試 Form 格式登入
func (ab *APIBruter) tryFormLogin(url, userField, passField string) *APIEndpoint {
	data := fmt.Sprintf("%s=test_detect_user&%s=test_detect_pass", userField, passField)
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ab.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	// 401 或 403 代表端點存在但認證失敗
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		ab.baseResp = string(bodyBytes)
		return &APIEndpoint{
			URL:           url,
			Method:        "POST",
			UsernameField: userField,
			PasswordField: passField,
			ContentType:   "form",
			StatusCode:    resp.StatusCode,
		}
	}

	return nil
}

// BruteForceDefaultAPI 用預設帳密嘗試 API 登入
func (ab *APIBruter) BruteForceDefaultAPI() []BruteResult {
	fmt.Printf("      測試 %d 組預設帳密...\n", len(DefaultCredentials))

	for _, cred := range DefaultCredentials {
		success, detail := ab.tryAPILogin(cred.User, cred.Pass)
		if success {
			result := BruteResult{
				Username: cred.User,
				Password: cred.Pass,
				Success:  true,
				Detail:   detail,
			}
			fmt.Printf("      [!!!] API 預設帳密破解成功! 帳號=%s 密碼=%s\n", cred.User, cred.Pass)
			ab.mu.Lock()
			ab.Results = append(ab.Results, result)
			ab.mu.Unlock()
		}
	}
	return ab.Results
}

// BruteForceWithWordlistAPI 用字典檔爆破 API 登入
func (ab *APIBruter) BruteForceWithWordlistAPI(users, passwords []string, threads int) []BruteResult {
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
				success, detail := ab.tryAPILogin(t.user, t.pass)
				if success {
					ab.mu.Lock()
					ab.Results = append(ab.Results, BruteResult{
						Username: t.user,
						Password: t.pass,
						Success:  true,
						Detail:   detail,
					})
					ab.mu.Unlock()
					fmt.Printf("\n      [!!!] API 爆破成功! 帳號=%s 密碼=%s\n", t.user, t.pass)
				}
				ab.mu.Lock()
				attempted++
				ab.mu.Unlock()
				wg.Done()
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ab.mu.Lock()
				pct := float64(attempted) / float64(total) * 100
				ab.mu.Unlock()
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

	return ab.Results
}

// tryAPILogin 嘗試 API 登入一次
func (ab *APIBruter) tryAPILogin(username, password string) (bool, string) {
	if ab.Endpoint == nil {
		return false, "無 API 端點"
	}

	var req *http.Request
	var err error

	if ab.Endpoint.ContentType == "json" {
		payload := map[string]string{
			ab.Endpoint.UsernameField: username,
			ab.Endpoint.PasswordField: password,
		}
		jsonBytes, _ := json.Marshal(payload)
		req, err = http.NewRequest("POST", ab.Endpoint.URL, bytes.NewReader(jsonBytes))
		if err != nil {
			return false, err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
	} else {
		data := fmt.Sprintf("%s=%s&%s=%s",
			ab.Endpoint.UsernameField, username,
			ab.Endpoint.PasswordField, password)
		req, err = http.NewRequest("POST", ab.Endpoint.URL, strings.NewReader(data))
		if err != nil {
			return false, err.Error()
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := ab.client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	body := string(bodyBytes)
	bodyLower := strings.ToLower(body)

	// 判斷登入成功:

	// 1. 原本回 401，現在回 200 = 成功
	if ab.Endpoint.StatusCode == 401 && resp.StatusCode == 200 {
		return true, fmt.Sprintf("API 回應 200 (原為 401)")
	}

	// 2. 回應中有 token
	if resp.StatusCode == 200 {
		if strings.Contains(bodyLower, "token") ||
			strings.Contains(bodyLower, "access_token") ||
			strings.Contains(bodyLower, "jwt") ||
			strings.Contains(bodyLower, "session") {
			// 但要排除錯誤訊息中剛好包含這些字
			if !strings.Contains(bodyLower, "invalid") &&
				!strings.Contains(bodyLower, "error") &&
				!strings.Contains(bodyLower, "failed") &&
				!strings.Contains(bodyLower, "incorrect") {
				return true, fmt.Sprintf("API 回應包含 token/session")
			}
		}
	}

	// 3. 回應跟失敗基準明顯不同
	if resp.StatusCode == 200 && len(ab.baseResp) > 0 {
		diff := len(body) - len(ab.baseResp)
		if diff < 0 {
			diff = -diff
		}
		ratio := float64(diff) / float64(len(ab.baseResp))
		if ratio > 0.3 && !strings.Contains(bodyLower, "error") && !strings.Contains(bodyLower, "invalid") {
			return true, fmt.Sprintf("API 回應長度差異 %.0f%% (建議人工驗證)", ratio*100)
		}
	}

	// 4. 成功指標關鍵字
	successWords := []string{"success", "ok", "登入成功", "welcome"}
	for _, w := range successWords {
		if strings.Contains(bodyLower, w) &&
			!strings.Contains(bodyLower, "error") &&
			!strings.Contains(bodyLower, "fail") {
			return true, fmt.Sprintf("API 回應包含成功指標: %s", w)
		}
	}

	return false, ""
}
