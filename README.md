# 🛡️ ssdeep-scanner

**CLI-based Heuristic Malware Scanner (Go Edition)**  
โปรแกรมสแกนไฟล์ด้วยเทคนิค **ssdeep (Fuzzy Hashing)** เพื่อเปรียบเทียบความเหมือนกับฐานข้อมูลลายเซ็นมัลแวร์ ทำงานได้อย่างรวดเร็ว รองรับระบบปฏิบัติการ Windows และ Linux พร้อมระบบคัดกรองผลลัพธ์ที่แม่นยำ (False Positive Suppression) แบบ 4 ชั้น

---

## ✨ ฟีเจอร์เด่น (Key Features)

| ฟีเจอร์ | รายละเอียด |
|---------|------------|
| **🎯 Heuristic Scan** | ค้นหามัลแวร์จากการเปรียบเทียบความเหมือน (Fuzzy Hashing) ด้วย ssdeep (ค่าเริ่มต้น Threshold 85%) |
| **🔐 Authenticode Check** | ตรวจสอบ Digital Signature (เฉพาะ Windows) หากมาจาก CA ที่ถูกต้อง จะข้ามการแจ้งเตือนทันที |
| **🏢 Publisher Check** | ตรวจสอบชื่อบริษัท (CompanyName) เทียบกับ Trusted List หากตรงกันจะแจ้งเตือนเป็นแค่ `[WARN]` |
| **🧠 ML Filter (XGBoost)** | ใช้ Machine Learning กรองความน่าจะเป็นในการเป็นมัลแวร์ ช่วยลดผลบวกปลอม (False Positive) |
| **🌐 VirusTotal Sync** | ดึงคะแนนการตรวจจับจาก VirusTotal หากผลลัพธ์เป็น 0 จะซ่อนการแจ้งเตือนอัตโนมัติ |
| **⚡ Smart Cache** | จดจำไฟล์ที่เคยสแกนแล้ว หากไฟล์ไม่มีการเปลี่ยนแปลง จะข้ามการสแกนเพื่อความรวดเร็ว |
| **📥 Signature Import** | รองรับการเพิ่มลายเซ็นมัลแวร์จากไฟล์ `.json`, `.sql`, `.csv` หรือดึงจาก VirusTotal ผ่าน Hash |
| **🚫 Duplicate Check** | ป้องกันการเพิ่มลายเซ็นมัลแวร์ซ้ำซ้อนลงในฐานข้อมูล |
| **🚀 High Velocity** | ดึงประสิทธิภาพ CPU Multi-core และ RAM มาใช้อย่างเต็มที่ สแกนได้รวดเร็ว |
| **💻 Cross-Platform** | รองรับการทำงานทั้งบน Windows และ Linux (x64, ARM64) |

---

## ⚙️ ความต้องการของระบบ & การติดตั้ง

- **ต้องการ:** Go 1.25+ (สำหรับการ Build จาก Source Code)

## 🪟 Windows

go build -o scanner.exe .
scanner.exe

## Linux / macOS
### ติดตั้ง dependencies สำหรับ GUI Popup (ทางเลือก)
sudo apt install zenity kdialog 

### Build และกำหนดสิทธิ์
go build -o scanner_linux .
chmod +x scanner_linux
./scanner_linux

### Cross-compile จาก Windows → Linux

## รันบน Windows Command Prompt เพื่อสร้างไฟล์ให้ Linux
set GOOS=linux
set GOARCH=amd64
go build -o scanner_linux .

## สำหรับ Linux ARM (เช่น Raspberry Pi)
GOOS=linux GOARCH=arm64 go build -o scanner_linux_arm64 .

---

## คู่มือการใช้งาน
scanner.exe      # Windows
./scanner_linux  # Linux
### โหมด Interactive (เมนูหลัก)
```
  [1] Select folder via GUI Popup
  [2] Specify directory path manually
  [3] Scan entire system (All Drives)
  [4] Import Signatures (File / VirusTotal)
  [5] Change Threshold
  [6] Configure Target Extensions
  [7] Toggle Suppress Clean VT [Current: ON]
  [8] Clear Cache Database (cache.db)
  [9] Exit Scanner
```

| ตัวเลือก | การทำงาน |
|----------|----------|
| **1** | เปิด popup เลือกโฟลเดอร์ |
| **2** | พิมพ์ path โฟลเดอร์ที่ต้องการสแกน |
| **3** | สแกนทุก drive (Windows) หรือ mount point หลัก (Linux) |
| **4** | เพิ่มลายเซ็นเข้าฐานข้อมูล (ดูรายละเอียดด้านล่าง) |
| **5** | เปลี่ยนค่า Threshold |
| **6** | ตั้งค่านามสกุลไฟล์ (Extensions) |
| **7** | เปิด/ปิด (ถ้า VirusTotal เป็น 0 ไม่แสดงผล) |
| **8** | ลบ cache (ลบผลลัพธ์ก่อนหน้า) |
| **9** | ออกจากโปรแกรม |

โหมด Command Line (CLI Flags)
เหมาะสำหรับผู้ใช้ขั้นสูง หรือการนำไปตั้งค่าทำงานอัตโนมัติ (Automated Scripts)
💡 Tip: สามารถวาง Flag ไว้ตำแหน่งใดก็ได้ (หน้า หรือ หลัง Path โฟลเดอร์ ก็ได้)

Flag	| คำอธิบาย	| ตัวอย่างการใช้งาน
-threshold <0-100>	|กำหนดเปอร์เซ็นต์ความเหมือนที่จะตัดสินว่าเป็นมัลแวร์|	scanner -threshold 80 C:\
-clear-cache	|ลบไฟล์ cache.db เพื่อบังคับสแกนใหม่ทั้งหมด|	scanner -clear-cache /tmp
-config-ext	|ตั้งค่านามสกุลไฟล์ที่ต้องการสแกน (เช่น .exe, .dll)|	scanner -config-ext
-suppress-vt=false|	ปิดการซ่อนผลลัพธ์ (แสดงไฟล์ทั้งหมดแม้ VT ตรวจไม่พบ)|	scanner -suppress-vt=false C:\
-offline	|ปิดระบบ VirusTotal และรันแบบออฟไลน์ 100%|	scanner -offline /home
-import <file>	|นำเข้าลายเซ็นจากไฟล์ .csv, .json, .sql|	scanner -import sig.csv
--add-sig	|เพิ่มลายเซ็นแบบ Manual (ชื่อมัลแวร์ ssdeep)|	scanner --add-sig "EICAR" "3:a..."
--vt-import	|ดึง ssdeep จาก VT ผ่าน Hash (Hash ชื่อ)|	scanner --vt-import "hash" "EICAR"

ตัวอย่างการรันแบบผสมคำสั่ง:
### สแกนโฟลเดอร์ Downloads โดยลบ Cache เก่าทิ้ง และตั้ง Threshold ที่ 90%
scanner.exe C:\Users\Admin\Downloads -clear-cache -threshold 90

### รันออฟไลน์ สแกน 2 โฟลเดอร์พร้อมกัน และให้แสดงผลไฟล์ทั้งหมด (ไม่ซ่อนผล)
./scanner_linux /tmp /opt -offline -suppress-vt=false


### รายละเอียดการสแกน

| รายการ | ค่า |
|--------|-----|
| **Similarity Threshold** | **85%** ขึ้นไปถึงแจ้งเตือน | default
| **FP Suppression** | ถ้า VT ยืนยัน 0 detections → ข้าม alert อัตโนมัติหรือ CLEAN ถ้าเปิดการแจ้งเตือน|
| **ขนาดไฟล์ขั้นต่ำ** | 4 KB + 1 byte|
| **ขนาดไฟล์สูงสุด** | 50 MB |
| **นามสกุลที่สแกน** | 	
.com, .msi, .msp, .scr, .pif, .cpl, .msc, .exe, .dll, .sys, .ps1,
.bat, .cmd, .vbs, .vbe, .jse, .wsf, .hta, .inf, .lnk, .url,
.docm, .xlsm, .pptm, .rtf, .sh, .py, .jar, .so, .dmg, .pkg, .command

### Logic การตัดสิน Alert (4-Layer)

```
[ เริ่มต้น ] ssdeep match ข้ามเกณฑ์ที่กำหนด (เช่น ≥ 85%)
   │
   ▼
[ Layer 1: Authenticode ] (เฉพาะ Windows)
   ├─ ลายเซ็นดิจิทัลถูกต้อง (Valid CA) ───> ซ่อนผลลัพธ์ (ปลอดภัย)
   └─ ไม่มีลายเซ็น / ไม่ถูกต้อง ──────────> ไปต่อ Layer 2
   │
   ▼
[ Layer 2: Trusted Publisher ] (เฉพาะ Windows)
   ├─ CompanyName ตรงกับ Trusted List ──> แจ้งเตือน [WARN] สีเหลือง (อาจเป็นโปรแกรมถูกกฎหมาย)
   └─ ไม่ตรง / ไม่มีข้อมูล ───────────────> ไปต่อ Layer 3
   │
   ▼
[ Layer 3: ML Filter (XGBoost) ]
   │ (วิเคราะห์จาก: fileSize, entropy (≥7), blockSize, numSections)
   ├─ โอกาสเป็นมัลแวร์ ≤ 0.587 ────────> มองว่าเป็น False Positive
   └─ โอกาสเป็นมัลแวร์ > 0.587 ────────> ไปต่อ Layer 4
   │
   ▼        
[ Layer 4: VirusTotal Check ] (หากใส่ API Key)
   ├─ VT พบ 0 Detections ─────────────> ซ่อนผลลัพธ์ (หรือแสดงตามตั้งค่า Suppress-VT)
   ├─ VT พบ ≥ 1 Detections ───────────> แจ้งเตือน [ALERT] | VT: X/Y
   └─ VT ไม่พบข้อมูล / Error ───────────> แจ้งเตือน [ALERT] | VT: Unknown/Error
```

> **หมายเหตุ:** Layer 1 และ 2 ทำงานเฉพาะบน **Windows** เท่านั้น (Authenticode และ PE Version Info เป็น Windows-specific)

### โฟลเดอร์ที่ข้าม
| ระบบ | โฟลเดอร์ |
|------|----------|
| Windows | `windows\winsxs`, `$Recycle.Bin`, `System Volume Information`, `$Windows.~BT`, `$Windows.~WS` |
| Linux | `proc`, `sys`, `dev`, `run`, `snap`, `lost+found` |

---

## ตัวอย่าง Output

### หน้าจอสแกน

```
  _   _                      _     _   _
 | | | | ___ _   _ _ __ _   _| |___| |_(_) ___
 | |_| |/ _ \ | | | '__| | | | / __| __| |/ __|
 |  _  |  __/ |_| | |  | |_| | \__ \ |_| | (__
 |_| |_|\___|\_,_|_|   \__,_|_|___/\__|_|\___|

       CLI-based Heuristic Malware Scanner (Go Edition)

[*] Detected drives: C:\, D:\
[*] Loading cache data into memory...
[*] Pre-loading signatures...
[*] Total signatures : 777687 items.
[*] Current Threshold: 85%
[*] Target Extensions: .exe, .dll, .bat, .ps1, .sh, .py ...

[ALERT] malware.exe | Path: C:\Downloads    | Match: 91% | Family: Trojan | VT: 52/72
[WARN]  python.exe  | Path: C:\myenv\Scripts| Match: 87% | Family: Trojan | ⚠ Unverified Publisher: Python Software Foundation

Scanned: 1240 files... Done!
```

### Scan Summary

```
=== Scan Summary ===
Total files scanned       : 1240
Files skipped (Size/Ext)  : 8432
Files skipped (Cache)     : 3201
Suppressed (Authenticode) : 12
Warnings  (Unverified Pub): 3
Suppressed (VT: 0 det.)   : 2
Threats detected          : 1
Time elapsed              : 12.45 seconds
```

| บรรทัด Summary | ความหมาย |
|---------------|----------|
| `Suppressed (Authenticode)` | ไฟล์ที่มี valid digital signature → ปลอดภัย suppress เงียบๆ |
| `Warnings (Unverified Pub)` | ไฟล์ที่ CompanyName match trusted list แต่ไม่มี signature → ควรตรวจสอบเอง |
| `Suppressed (VT: 0 det.)` | ไฟล์ที่ VT ยืนยัน 0 detections → suppress (ต้องมี VT key) |

---

## คู่มือการเพิ่มลายเซ็น (Database)

มี 5 วิธีในการเพิ่มข้อมูลมัลแวร์เข้าฐานข้อมูล `signatures.db`:

---

### วิธีที่ 1 — Import จากไฟล์ CSV ⭐ แนะนำ

เหมาะสำหรับ: มีข้อมูลมัลแวร์หลายรายการในรูป Spreadsheet หรือ Excel

**รูปแบบ CSV ที่รองรับ:**

**3 คอลัมน์** (มี family):
```csv
name,family,ssdeep
Trojan.Generic,Backdoor,768:abc123:def456
Worm.Conficker,Worm,384:xyz789:uvw012
Ransomware.WannaCry,Ransomware,192:qqq111:rrr222
```

**2 คอลัมน์** (ไม่มี family):
```csv
name,ssdeep
Trojan.Generic,768:abc123:def456
Worm.Conficker,384:xyz789:uvw012
```

> **หมายเหตุ:**
> - Header row (บรรทัดแรก) จะถูกข้ามอัตโนมัติ
> - รองรับค่าที่ถูก quote เช่น `"Trojan, Generic"`

**วิธีรัน:**

```bash
# ผ่าน CLI flag
scanner.exe -import C:\signatures.csv
./scanner_linux -import /home/user/signatures.csv

# ผ่านเมนู → เลือก [4] → เลือก [a]
```

---

### วิธีที่ 2 — Import จากไฟล์ JSON

เหมาะสำหรับ: มีไฟล์ signatures จาก threat intelligence feeds

**รูปแบบ JSON:**
```json
[
  {
    "name": "Trojan.Generic",
    "family": "Backdoor",
    "ssdeep": "768:abc123xyz:def456uvw"
  },
  {
    "name": "Worm.Conficker",
    "family": "Worm",
    "ssdeep": "384:xyz789abc:uvw012def"
  }
]
```

**วิธีรัน:**
```bash
scanner.exe -import signatures.json
./scanner_linux -import signatures.json
```

---

### วิธีที่ 3 — Import จากไฟล์ SQL

เหมาะสำหรับ: มีไฟล์ dump จากฐานข้อมูลมัลแวร์อื่น

**รูปแบบ SQL ที่รองรับ:**
```sql
INSERT INTO `malware_signatures` VALUES ('Trojan.Generic', 'Backdoor', '768:abc123:def456');
INSERT INTO malware_signatures VALUES ('Worm.Agent', 'Worm', '384:xyz:uvw');
```

**วิธีรัน:**
```bash
scanner.exe -import malware_db.sql
./scanner_linux -import malware_db.sql
```

---

### วิธีที่ 4 — ดึงจาก VirusTotal ด้วย SHA256 / SHA1

เหมาะสำหรับ: มีแค่ SHA256 หรือ SHA1 ของไฟล์มัลแวร์ แต่ไม่มีไฟล์จริง

> **ต้องมี VT API key ใน `vt_keys.txt` ก่อน**

**วิธีรัน:**
```bash
# ผ่าน CLI flag
scanner.exe --vt-import "SHA256_OR_SHA1_HASH" "MalwareName"

# ตัวอย่าง
scanner.exe --vt-import "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" "Trojan.EICAR"

# ผ่านเมนู → เลือก [4] → เลือก [b]
```

**ผลลัพธ์:**
```
[*] Querying VirusTotal for: 275a021b...
[+] ssdeep retrieved: 3:aNZGQ:aNZGQ
[+] Added 'Trojan.EICAR' (Block Size: 3) to signatures.
```

**Error ที่อาจพบ:**

| ข้อความ | สาเหตุ |
|---------|--------|
| `no VT API keys configured` | ไม่มีไฟล์ `vt_keys.txt` หรือไม่มี key |
| `not found on VirusTotal` | hash ไม่มีในฐาน VT |
| `ssdeep hash not available` | VT มีไฟล์แต่ไม่มีข้อมูล ssdeep |
| `all N keys exhausted` | ทุก key โดน rate limit (429) |

---

### วิธีที่ 5 — เพิ่มทีละรายการด้วย ssdeep hash โดยตรง

เหมาะสำหรับ: มีไฟล์มัลแวร์จริงและคำนวณ ssdeep hash เองแล้ว

```bash
scanner.exe --add-sig "MalwareName" "blocksize:hash1:hash2"

# ตัวอย่าง
scanner.exe --add-sig "Trojan.Generic" "768:abc123xyz:def456uvw"
```

---

## Duplicate Check

โปรแกรมจะตรวจสอบลายเซ็นซ้ำทุกครั้งก่อน insert:

```
[+] Import successful: 5 signatures.
[!] Duplicates skipped: 3 items (already in database).
[!] Invalid/missing ssdeep entries skipped: 1 items.
```

---

## การตั้งค่า VirusTotal

1. สมัคร account ที่ [virustotal.com](https://www.virustotal.com) และรับ API key
2. สร้างไฟล์ `vt_keys.txt` ในโฟลเดอร์เดียวกับ `scanner.exe`:

```
# vt_keys.txt — ใส่ key ตรงนี้ (บรรทัดที่ขึ้น # จะถูกข้าม)
your_api_key_1_here
your_api_key_2_here
```

- รองรับหลาย key — โปรแกรมจะวน (round-robin) อัตโนมัติเมื่อโดน rate limit
- ถ้าไม่มีไฟล์ โปรแกรมยังทำงานได้ แต่ไม่แสดงผล VT และไม่กรอง false positive 

---

## สรุปวิธีเพิ่มลายเซ็นเปรียบเทียบ

| วิธี | ข้อมูลที่ต้องมี | เหมาะกับ |
|------|----------------|----------|
| `-import file.csv` | ชื่อ + ssdeep hash (CSV) | bulk import จาก Excel/Spreadsheet |
| `-import file.json` | ชื่อ + ssdeep hash (JSON) | threat intelligence feeds |
| `-import file.sql` | SQL dump | ย้ายข้อมูลจากฐานข้อมูลอื่น |
| `--vt-import SHA256 "Name"` | SHA256 หรือ SHA1 + ชื่อ | ไม่มีไฟล์จริง มีแค่ hash |
| `--add-sig "Name" "hash"` | ssdeep full hash + ชื่อ | เพิ่มทีละรายการ |

---

## ตัวอย่างการตั้งค่า Threshold

- เหมาะสำหรับกำหนดว่าอยากให้เหมือนกับไฟล์ที่อยู่ในฐานข้อมูลกี่เปอร์เซน
| `Enter new Threshold score (0-100):` ***| ให้เลือกระหว่างค่า 0 จนถึง 100|
| ` Enter new Threshold score (0-100): 75`| ตัวอย่างในการกรอก 75
| `[+] Successfully changed Threshold to: 75`| กรอกค่า 75 สำเร็จ
- กรณีที่กรอกน้อยกว่า 0
| Enter new Threshold score (0-100): -11 |
| [!] Threshold must be between 0 and 100.|
- กรณีที่กรอกน้อยกว่า 100
| Enter new Threshold score (0-100): 111 |
| [!] Threshold must be between 0 and 100.|


## ตัวอย่างการตั้งค่า Extension
- เหมาะสำหรับกำหนดว่าอยากให้สแกนนามสกุลไฟล์ไหนบ้าง หรือถ้าเบื้องต้องสแกนทั้งหมด

| **=== Configure Target Extensions ===** |
|`Enter EXACT extensions to scan separated by commas (e.g., .exe, .dll).`| กรอกค่านามสกุลไฟล์ที่ต้องการ
|`Type 'all' to scan all predefined script/executable extensions > .***, .***, .***`| พิมพ์ `all` , นามสกุลไฟล์ที่ต้องการ
|`Type 'all' to scan all predefined script/executable extensions > .exe, .dll, .so`| ตัวอย่างการกรอก
|`[+] Scanner will EXACTLY and ONLY scan: .exe, .dll, .so`| สแกนเฉพาะนามสถุลไฟล์ .exe, .dll, .so เท่านั้น
|`[*] Previous scan results have been reset.`| ผลลัพธ์ก่อนหน้ารีเซ็ต

## ตัวอย่างการตั้งค่าเปิด-ปิดค่า Suppress Clean VT
- เหมาะสำหรับอยากให้แสดงผลว่า เมื่อค่า VT = 0 det.
**[CLEAN]** edit_test.exe | Path: C:\Program Files\Git\mingw64\bin | Match: 91% | Family: b04ea3c83515c3daf2de76c18e72cb87c0772746ec7369acce8212891d0d8997.exe | VT: 0/70|

## ตัวอย่างการลบ cache.db 
- ใช้ทดสอบสแกนใหม่อีกครั้งถ้ามี cache.db แล้วอยากให้สแกนใหม่โดยไม่ดึงข้อมูลจาก cache
|`Please select an option (1-9) > 8`|
- กรณีที่มีไฟล์ cache.db
|`[+] Successfully deleted cache.db`| ลบสำเร็จ
-กรณีที่มีไม่มีไฟล์ cache.db
|`[!] Cache database (cache.db) does not exist.`| ไม่มีฐานข้อมูลชื่อว่า cache.db

## สรุปวิธีการสแกนผ่าน CLI flags

| วิธี                | การใช้งาน           
|-------------------|--------               
| `-clear-cache`    | ลบฐานข้อมูลที่เป็นผลลัพธ์เก่า ทำให้สามารถทดสอบซ้ำจากการเทียบค่าคล้ายคลึงกันได้
| `-config-ext`     | การตั้งค่านามสกุลไฟล์ (File Extension) เพื่อเจาะจงสกุลไฟล์เฉพาะที่ต้องการหรือทั้งหมดก็ได้
| `-suppress-vt`    | เปิด/ปิด การแสดงผลลัพธ์ ถ้าสแกนแล้วได้ค่า VT=0 สามารถกรอกได้ค่า 0,false(เปิดการแสดงผล) และ 1,true(ปิดการแสดงผล)
| `-threshold int`  | ตั้งค่าความคล้ายคลึงกันหรือเหมือนกันเท่าไร (แนะนำที่ 85 ) แต่เกณฑ์หลักอยู่ช่วง(65-95)



## โครงสร้างโปรเจ็ค

```
ssdeep-scanner/
├── main.go                  # Entry point, เมนู, CLI Flags
├── scanner.go               # ระบบสแกนหลัก (Worker pool + 4-Layer Logic)
├── db.go                    # จัดการ SQLite (signatures.db, cache.db)
├── import.go / export.go    # นำเข้า/ส่งออก ฐานข้อมูลมัลแวร์
├── vt.go                    # ระบบเชื่อมต่อ VirusTotal API
├── signature.db             # ฐานข้อมูลที่ใช้เทียบกับไฟล์ที่ต้องการสแกน
├── trusted.go               # ระบบตรวจสอบ Publisher และ Authenticode
├── trusted_windows.go        # Windows-only: ตรวจ Authenticode ด้วย WinVerifyTrust และอ่าน CompanyName จาก PE Version Info
├── trusted_other.go          # โหลดรายชื่อ trusted publishers จาก embedded file และ override จาก trusted_publishers.txt บนดิสก์ 
├── trusted_publishers.txt   # รายชื่อ Publisher ที่เชื่อถือได้ (ผู้ใช้สร้างเองได้)
├── malware_model.bin        # โมเดล ML (XGBoost) สำหรับคัดกรองความน่าจะเป็น
├── vt_keys.txt              # ไฟล์เก็บ VT API Keys
└── README.md                # คู่มือฉบับนี้
```

---

## Trusted Publishers (การปรับแต่ง False Positive)

โปรแกรมมี trusted publisher list ฝังในตัว (`trusted_publishers.txt`) ครอบคลุม publisher ทั่วไปเช่น Microsoft, Python, Node.js, Git, Oracle ฯลฯ

### วิธีเพิ่ม Publisher เอง

แก้ไขไฟล์ `trusted_publishers.txt` ในโฟลเดอร์เดียวกับ `scanner.exe`:

```txt
# บรรทัดที่ขึ้นต้นด้วย # จะถูกข้าม
microsoft corporation
python software foundation
my custom company name
```

- ใช้ **partial match, case-insensitive** — พิมพ์แค่บางส่วนของชื่อก็ได้
- ถ้าไม่มีไฟล์นี้ โปรแกรมจะใช้ default list ที่ embed ไว้อัตโนมัติ
- ถ้ามีไฟล์นี้ → ใช้ไฟล์นี้แทน default list ทั้งหมด

### ดู CompanyName ของไฟล์ที่ต้องการเพิ่ม

เมื่อไฟล์ถูก match แต่ไม่อยู่ใน list โปรแกรมจะแสดง `[ALERT]` พร้อม `Publisher: xxx` ให้เห็นชัดเจน — นำชื่อนั้นไปเพิ่มใน `trusted_publishers.txt` ได้เลย

> **⚠ คำเตือน:** Publisher check ใช้เฉพาะเป็น hint เท่านั้น CompanyName ใน PE file ปลอมแปลงได้ง่าย ไฟล์ที่ไม่มี valid Authenticode signature ควรตรวจสอบเพิ่มเติมเสมอ

## ไฟล์ฐานข้อมูล

| ไฟล์ | การใช้งาน |
|------|-----------|
| `signatures.db` | เก็บ ssdeep signatures (malware_name, block_size, ssdeep_full) |
| `cache.db` | เก็บ path + mtime ไฟล์ที่สแกนแล้ว — ข้ามไฟล์ที่ไม่เปลี่ยนแปลงในการสแกนครั้งต่อไป |

ทั้งสองไฟล์สร้างอัตโนมัติในโฟลเดอร์เดียวกับ `scanner.exe` เมื่อรันครั้งแรก

---

## ใบอนุญาตและข้อจำกัด

- โปรเจกต์นี้พัฒนาขึ้นเพื่อการศึกษาและการวิเคราะห์เชิงพฤติกรรม (Heuristic Analysis)
- การใช้ VirusTotal API ต้องเป็นไปตาม Terms of Service ของผู้ให้บริการ
- Publisher Check เป็นเพียงตัวช่วยคัดกรองเบื้องต้น ไม่สามารถยืนยันความปลอดภัยได้ 100% หากไฟล์นั้นไม่มี Authenticode Signature ที่ถูกต้อง
