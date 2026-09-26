# Spike 0 — 在一般權限下能不能把連線歸因到 Agent 行程樹？

日期：2026-09-25　環境：Windows 11，一般使用者權限（非管理員），Go 1.27

## 結論：✅ 通過

| 指標 | 目標 | 實測 |
|---|---|---|
| Agent 樹內行程的命令列取得率 | ≥ 95% | **100%**（100 多個行程全部取得） |
| Agent 樹內行程的路徑取得率 | — | **100%** |
| 收集耗時 | < 3 s | **約 50 ms**（約 600 個行程 + 全部 TCP 連線） |
| 外部 TCP 連線（ESTABLISHED） | — | 約 80 條，其中約 20 條歸因到 Agent 樹 |

收集層零外部相依，只用了 `syscall` 呼叫以下 API：
- `GetExtendedTcpTable`
- Toolhelp 行程快照
- `QueryFullProcessImageNameW`
- `NtQueryInformationProcess(ProcessCommandLineInformation)`：只需要 `PROCESS_QUERY_LIMITED_INFORMATION` 權限，不必讀 PEB

## 實際看到的情況

```
■ Claude Desktop (MSIX 安裝版)
   → 160.79.104.10:443
   ├─ [agent:Claude Code] claude.exe  (數個 session)
   │    → 160.79.104.10:443, 34.149.66.165:443
   │  ├─ [MCP?] （某個 MCP server 執行檔）   ← 每個 session 各自啟動的 MCP server
```

「Claude Desktop → 多個 Claude Code session → 各自的 MCP 子行程 → 遠端位址」這條鏈可以完整重建。這正是靜態掃描器看不到的東西。

## 權限限制

- 在全部行程中，約三分之一回傳 `Access is denied`。這些是 SYSTEM 服務和其他工作階段的行程，**不在 Agent 樹內**。
- 影響：核心一（Agent 歸因）在一般權限下就能完整運作；核心二（入侵健檢）要看到所有行程，需要 `--elevated` 模式。這跟規格 §7 的預期一致。

## W1 必須處理的缺口

1. **遠端 IP 沒有名稱**。`160.79.104.10` 推測是 Anthropic API，`34.149.66.165` 是 GCP 的負載平衡器，但目前無法確認。→ 要用 DNS 快取（`DnsGetCacheDataTable` 加上只查快取的 `DnsQuery`）把 IP 對應回網域名稱。
2. **QUIC/UDP 看不到**。`GetExtendedUdpTable` 只提供本機端點，不提供遠端位址。瀏覽器、Electron 和部分 SDK 走 HTTP/3 的流量會漏掉。→ W1 先在報告中標示「TCP only」，P2 改用 ETW（Microsoft-Windows-Kernel-Network）。**這是目前最大的覆蓋風險。**
3. **PID 可能被重複使用**。Toolhelp 給的 PPID 可能指向一個已經結束、PID 又被新行程拿去用的父行程。→ 用 `GetProcessTimes` 比對：子行程的建立時間必須晚於父行程。
4. **Electron 的輔助行程**：例如 `--type=utility` 的網路服務行程。→ 同一種 Agent 的輔助行程要收合到主行程底下，連線也一併歸給主行程。
5. **分類器要擴充**：加入 Antigravity、Kiro、Trae 等，並以 MCP 設定檔的盤點結果為 MCP 子行程命名，取代目前的 `MCP?` 猜測。
6. **數位簽章**：WinVerifyTrust 加上簽署者名稱。
