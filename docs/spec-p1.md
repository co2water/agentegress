# agentegress — P1 規格與計畫

> 一句話定位：**看見 Windows 上每個 AI Agent 和它啟動的 MCP 連到哪裡，並做入侵健檢。判定由規則負責，AI 只負責解說，機器上的文字騙不動判定。**
> 起始日期：2026-09-25。本文件記錄計畫本身、實際做到的程度，以及和計畫不同的地方。

## 0. 設計決策

| # | 決策 | 理由 |
|---|---|---|
| D1 | P1 只做 Windows 開發者（Claude Code、Claude Desktop、Cursor、VS Code 等的使用者） | 開發者最早會用 MCP；一般使用者留到之後的版本 |
| D2 | 核心是**執行時的 Agent 連線歸因**，不做靜態設定掃描 | 靜態掃描已經有 SkillSpector、snyk/agent-scan、cisco mcp-scanner 等工具在做 |
| D3 | 判定由規則引擎負責，LLM 只做解說 | 主機上的字串可以被攻擊者控制，交給 LLM 判定可能被 prompt injection 翻盤 |

## 1. 和既有工具的差別

| | 靜態掃描器（SkillSpector、agent-scan…） | pipelock（代理式） | AgentSight（eBPF） | Sniffnet 等監控工具 | **agentegress** |
|---|---|---|---|---|---|
| 平台 | 跨平台 | 跨平台 | **Linux** | 跨平台 | **Windows** |
| 看設定檔 | ✅ | — | — | — | 只盤點，不深入掃描 |
| 看實際連線 | ❌ | 只看得到經過代理的流量 | ✅ | ✅ 但不知道屬於哪個 Agent | ✅ 被動觀察 |
| 行程樹歸因（Agent → MCP → 連線） | ❌ | ❌ | ✅ | ❌ | ✅ |
| 入侵健檢與資安判定 | ❌ | ❌ | ❌（定位是除錯與效能） | ❌ | ✅ |
| 透過 MCP 讓 AI 查詢，輸出有防注入處理 | 部分 | ❌ | ❌ | ❌ | ✅ |

## 2. P1 範圍

### A. 執行時 Agent 連線歸因

- 辨識 Agent 根行程：Claude Code、Claude Desktop（含 MSIX 安裝版）、Cursor、VS Code、Windsurf、Codex、Gemini CLI、opencode、Antigravity、Kiro、Trae、Goose、Aider、Copilot CLI、Amp。
- 建立行程樹：以建立時間防止 PID 重用造成誤判；Electron 輔助行程收合到主行程。
- 每條 TCP 連線和監聽埠都歸因到「Agent → 子行程 → 遠端位址」。遠端位址先查本機 DNS 快取，再查內嵌的官方 IP 範圍，標出所屬組織。
- 讀取 9 種客戶端的 MCP 設定檔，只用來幫行程命名，不做深入掃描。

### B. 入侵健檢

| 檢查項目 | 需要管理員權限？ | 狀態 |
|---|---|---|
| 對外連線或監聽的程式，是否有有效簽章；script host 載入的檔案也要檢查 | 否（其他使用者的行程需要） | ✅ |
| 常駐點：Run 登錄機碼、啟動資料夾、服務（含 svchost 載入的 DLL）、排程工作、Winlogon | 否（沒有權限時，排程工作只列出目前使用者看得到的） | ✅ |
| 登入紀錄：失敗登入（4625）、RDP 登入（4624 type 10） | **是** | 🟡 有單元測試，但還沒在真機上以管理員權限跑過 |
| 防火牆設定檔、RDP 開關 | 否 | ✅ |
| SMB 暴露狀態 | — | ❌ **P1 不做**（見 §9） |

### P1 不做的事

唯讀：不攔截、不結束行程、不改設定。不做常駐程式和系統匣視窗。不支援 macOS、Linux。不抓封包。工具內不內建 LLM。不連網。

## 3. 架構

```
collect/   行程、TCP、DNS 快取、簽章、常駐點、事件日誌、MCP 設定（主機字串一律視為不可信）
snapshot/  組成資料模型：行程樹、Agent 歸因、MCP 對應、連線標註、簽章、涵蓋範圍
engine/    12 條規則 → Finding{rule, severity, title, detail, untrusted_evidence}
render/    文字報告          mcptools/  MCP 工具（唯讀）          ack/  使用者確認
```

CLI 和 MCP 共用同一套引擎，所以兩邊的判定一定一致。

## 4. 規則

目前的規則表見 [README](../README.md#what-it-checks)。

## 5. 防 prompt injection 設計

1. **LLM 只做解說，不做判定。** 判定和嚴重度都由引擎計算。每個工具結果開頭都有固定說明，`scan_summary` 會附上 `must_report`。
2. **不可信資料隔離。** 所有主機文字只會出現在 `untrusted` 或 `untrusted_evidence` 底下，並先經過遮蔽和清洗：移除控制字元、隱形字元與格式字元、雙向控制字元、Unicode tag。MCP 輸出中，命令列截斷為 300 字元，其他欄位為 120 字元。
3. **Title 和 Detail 由程式寫定。** 由性質測試強制把關：每一條已註冊的規則都必須在測試中觸發，才算通過驗證。
4. **注入企圖本身就是入侵跡象**（規則 I1）。
5. **紅隊測試集**：`internal/fixtures/redteam.go` 和 `tools/redteam`，結果見 [w3.md](w3.md)。

## 6. MCP 工具

`scan_summary`、`list_findings`、`list_agents`、`list_connections`、`explain_process`、`list_listening_ports`、`list_autostarts`、`login_activity`，全部唯讀。

## 7. 隱私與權限

- 工具本身不連網：簽章驗證只用快取、DNS 只查本機快取。每次掃描都會做自我檢查，但檢查只看當下的 TCP 端點，不能當成完整的證明。
- 透過 MCP 使用時，工具結果會由使用者的 AI 客戶端送給它使用的模型供應商。這一點已寫進 README。
- 預設以一般權限執行；沒檢查到的項目會列在 `not_checked`。

## 8. 技術選型

| 項目 | 選擇 | 理由 |
|---|---|---|
| 語言 | Go | 單一執行檔，不需要另裝執行環境 |
| Windows API | 標準函式庫的 `syscall`（LazyDLL） | 零外部相依 |
| MCP | 自己實作 stdio 協定（原本計畫用官方 go-sdk，W3 改變決定） | 只用到 4 個方法，自己寫可以維持零外部相依 |

## 9. 里程碑與實際狀態

| 階段 | 計畫 | 實際狀態 |
|---|---|---|
| Spike 0 | 在一般權限下讀到 Agent 樹內行程的命令列 | ✅ 當時 122/122 都讀得到（這個 spike 的程式碼後來直接演變成 CLI，沒有另外保存） |
| W1 | 收集層、`scan` 報告，耗時 < 3 秒 | ✅ 功能完成。當時量到 0.36 秒，但加入常駐點檢查後變慢。目前在開發機上暖機後約 1.3–2.5 秒；冷啟動在獨立審查時曾量到約 7 秒，後來略過 System32 的簽章檢查才降下來，**冷啟動還沒重新量測** |
| W2 | 規則引擎、入侵健檢、JSON findings、遮蔽 | 🟡 12 條規則完成；**SMB 沒有做**；登入檢查的管理員權限路徑沒在真機上跑過；原本的 A5 已併入 A4 的 info 等級 |
| W3 | MCP server、防注入、紅隊測試 | ✅ 原本「翻盤 0 次」的驗收標準**分不出設計有沒有效果**（naive 對照組也是 0 次），因此改用公平重測：資料相同、隔離修好、13 個情境。agentegress 78/78；naive 在「合理藉口」和「證據不明顯」兩類情境 12 次只對 2 次，明顯注入則兩者沒有差別。見 [w3.md](w3.md) |
| W3.5 | 依獨立審查結果強化 | ✅ 兩輪程式審查（第一輪 14 項缺陷；第二輪 5 項修正不完整、4 項新缺陷，包括一個退步）和一次驗收稽核，全部修正並補上回歸測試，見 [review-2026-09-25.md](review-2026-09-25.md) |
| W4 | README、示範、發布流程 | 進行中 |

### 與原計畫的偏差（經獨立審查確認）

- SMB 暴露檢查：沒有做。要正確判斷需要知道目前生效的防火牆規則，以及 SMBv1 的安裝狀態，P1 決定不做。
- A5（目的地不在已知 AI 端點清單）：併入 A4 的 info 等級。
- MCP 工具：`list_persistence` 改名為 `list_autostarts`；`suspicious_only` 參數改成 `problems_only` 和 `agents_only`。
- 紅隊測試集放在 `internal/fixtures` 和 `tools/redteam`，不是原本計畫的 `tests/injection/`；目前也還沒有「事件日誌文字注入」的情境。
- 證據的截斷長度：引擎的 `untrusted_evidence` 截在 300 字元；MCP 輸出照 §5 的規定（命令列 300、其他 120）。

## 10. 風險

- **防毒誤判**：測試資料含有攻擊字串，這些字串只要出現在行程命令列上，Defender 就會擋下，開發過程中已經發生過 3 次。因此規定測試資料只能寫在檔案裡。
- **遠端 IP 查不到名稱**：DNS 快取幾乎沒有用。主要靠內嵌的官方 IP 範圍；沒有公布範圍的供應商（Azure、多數亞洲業者）就沒有標籤。
- **只看得到 TCP**：看不到 QUIC/UDP。
