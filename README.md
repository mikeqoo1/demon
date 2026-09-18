# demon
資訊安全 — Go 滲透測試工具箱（僅供教學與授權測試）

## 建置

```bash
make build   # 編譯所有執行檔到 bin/
make test    # 執行單元測試
```

## 文件說明

```txt
├── demo                # 各個可執行程式
│   ├── pentest         # 整合式滲透測試（掃描→爆破→Web檢測→產報告）
│   ├── scan            # 全端口掃描
│   ├── sshBoom         # SSH 帳密爆破
│   ├── reverse         # reverse shell（server / client）
│   └── keylogger       # 鍵盤側錄
├── internal
│   ├── attack          # SSH 登入、reverse shell 用戶端
│   ├── scan            # 端口解析、有界並行掃描、漏洞對應
│   ├── webscan         # Web 檢測：標頭/TLS/路徑/方法、SQLi、登入與 API 爆破
│   ├── report          # Markdown 報告產生
│   ├── logger          # Zap 日誌封裝
│   ├── dblib           # MySQL 連線封裝
│   └── help            # 檔案讀取小工具
```

## 使用範例

```bash
bin/Pentest.out -url https://target.example.com -tester Mike
bin/Pentest.out -ip 192.168.1.1 -url https://target.example.com -users user.txt -passwords password.txt
```
