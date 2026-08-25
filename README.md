# 🛡️ ssdeep-scanner

**CLI-based Heuristic Malware Scanner (Go Edition)**  
โปรแกรมสแกนไฟล์ด้วยเทคนิค **ssdeep (Fuzzy Hashing)** เพื่อเปรียบเทียบความเหมือนกับฐานข้อมูลลายเซ็นมัลแวร์ ทำงานได้อย่างรวดเร็ว รองรับระบบปฏิบัติการ Windows และ Linux พร้อมระบบคัดกรองผลลัพธ์ที่แม่นยำ (False Positive Suppression) แบบ 4 ชั้น

---

## ✨ ฟีเจอร์เด่น (Key Features)

| ฟีเจอร์ | รายละเอียด |
| :--- | :--- |
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

> **Requirement:** Go 1.25+ (สำหรับการ Build จาก Source Code)

### 🪟 Windows

```powershell
# Build และรันโปรแกรม
go build -o scanner.exe .
.\scanner.exe
```

### 🐧 Linux / macOS

```bash
# ติดตั้ง dependencies สำหรับ GUI Popup (ทางเลือก)
sudo apt update && sudo apt install -y zenity kdialog

# Build และกำหนดสิทธิ์รัน
go build -o scanner_linux .
chmod +x scanner_linux
./scanner_linux
```

### 🔄 Cross-Compile (จาก Windows → Linux)

```cmd
:: รันบน Windows Command Prompt เพื่อสร้างไฟล์สำหรับ Linux x64
set GOOS=linux
set GOARCH=amd64
go build -o scanner_linux .

:: สำหรับ Linux ARM64 (เช่น Raspberry Pi / ARM Server)
set GOOS=linux
set GOARCH=arm64
go build -o scanner_linux_arm64 .
```

---

## 🚀 คู่มือการใช้งาน

```bash
scanner.exe      # สำหรับ Windows
./scanner_linux  # สำหรับ Linux
```

### 🖥️ 1. โหมด Interactive (เมนูหลัก)

```text
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
| :---: | :--- |
| **1** | เปิด GUI Popup สำหรับเลือกโฟลเดอร์ที่ต้องการสแกน |
| **2** | ป้อน Path โฟลเดอร์ด้วยตนเอง |
| **3** | สแกนทุก Drive (Windows) หรือ Mount Point หลัก (Linux) |
| **4** | เพิ่มลายเซ็นมัลแวร์เข้าฐานข้อมูล |
| **5** | เปลี่ยนค่าเปอร์เซ็นต์ความคล้ายคลึง (Threshold Score) |
| **6** | ตั้งค่านามสกุลไฟล์ที่ต้องการสแกน |
| **7** | สลับสถานะ เปิด/ปิด การซ่อนผลลัพธ์กรณี VirusTotal ตรวจไม่พบ (VT = 0) |
| **8** | ล้างไฟล์ Cache (`cache.db`) เพื่อบังคับสแกนใหม่ทั้งหมด |
| **9** | ออกจากโปรแกรม |

---

### 💻 2. โหมด Command Line (CLI Flags)

เหมาะสำหรับการนำไปใช้กับ Automated Script หรือผู้ใช้ขั้นสูง *(สามารถวาง Flag ไว้หน้าหรือหลัง Path โฟลเดอร์ก็ได้)*

| Flag | คำอธิบาย | ตัวอย่างการใช้งาน |
| :--- | :--- | :--- |
| `-threshold <0-100>` | กำหนดเปอร์เซ็นต์ความเหมือนที่ต้องการแจ้งเตือน | `scanner -threshold 80 C:\` |
| `-clear-cache` | ลบไฟล์ `cache.db` เพื่อสแกนใหม่ทั้งหมด | `scanner -clear-cache /tmp` |
| `-config-ext` | ตั้งค่านามสกุลไฟล์ที่ต้องการสแกน | `scanner -config-ext` |
| `-suppress-vt=false` | ปิดการซ่อนผลลัพธ์ (แสดงแม้ VT ตรวจไม่พบ) | `scanner -suppress-vt=false C:\` |
| `-offline` | ปิดการเชื่อมต่อ VirusTotal และทำงานแบบ ออฟไลน์ 100% | `scanner -offline /home` |
| `-import <file>` | นำเข้าลายเซ็นจากไฟล์ `.csv`, `.json`, `.sql` | `scanner -import sig.csv` |
| `--add-sig` | เพิ่มลายเซ็นมัลแวร์แบบ Manual | `scanner --add-sig "EICAR" "3:a..."` |
| `--vt-import` | ดึง ssdeep จาก VirusTotal ผ่าน File Hash | `scanner --vt-import "hash" "EICAR"` |

#### 💡 ตัวอย่างคำสั่งรันแบบผสม:

```bash
# สแกนโฟลเดอร์ Downloads โดยลบ Cache เก่า และตั้งค่า Threshold ที่ 90%
scanner.exe C:\Users\Admin\Downloads -clear-cache -threshold 90

# รันแบบออฟไลน์ สแกนพร้อมกัน 2 โฟลเดอร์ และแสดงผลไฟล์ทั้งหมด
./scanner_linux /tmp /opt -offline -suppress-vt=false
```

---

## 🔍 สเปกและพฤติกรรมการสแกน

### 📌 รายละเอียดการตั้งค่าพื้นฐาน

* **Similarity Threshold:** `85%` ขึ้นไป (ค่าเริ่มต้น)
* **FP Suppression:** ข้ามการแจ้งเตือนอัตโนมัติหรือแสดงเป็น `CLEAN` หาก VirusTotal ยืนยัน 0 detections
* **ขนาดไฟล์:** สแกนเฉพาะไฟล์ขนาดระหว่าง **4 KB + 1 byte** ถึง **50 MB**
* **นามสกุลที่รองรับ:** `.com`, `.msi`, `.msp`, `.scr`, `.pif`, `.cpl`, `.msc`, `.exe`, `.dll`, `.sys`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.vbe`, `.jse`, `.wsf`, `.hta`, `.inf`, `.lnk`, `.url`, `.docm`, `.xlsm`, `.pptm`, `.rtf`, `.sh`, `.py`, `.jar`, `.so`, `.dmg`, `.pkg`, `.command`

### 🛡️ Logic การตัดสิน Alert (4-Layer Filtering)

```text
[ เริ่มต้น ] ssdeep match ข้ามเกณฑ์ที่กำหนด (เช่น ≥ 85%)
   │
   ▼
[ Layer 1: Authenticode ] (เฉพาะ Windows)
   ├─ ลายเซ็นดิจิทัลถูกต้อง (Valid CA) ───> ซ่อนผลลัพธ์ (ปลอดภัย)
   └─ ไม่มีลายเซ็น / ไม่ถูกต้อง ──────────> ไปต่อ Layer 2
   │
   ▼
[ Layer 2: Trusted Publisher ] (เฉพาะ Windows)
   ├─ CompanyName ตรงกับ Trusted List ──> แจ้งเตือน [WARN] สีเหลือง
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

> **หมายเหตุ:** Layer 1 และ Layer 2 ทำงานเฉพาะบน **Windows** เท่านั้น เนื่องจากขึ้นกับ Authenticode และ PE Version Info

### 🚫 โฟลเดอร์ที่ข้ามการสแกนอัตโนมัติ

* **Windows:** `windows\winsxs`, `$Recycle.Bin`, `System Volume Information`, `$Windows.~BT`, `$Windows.~WS`
* **Linux:** `proc`, `sys`, `dev`, `run`, `snap`, `lost+found`

---

## 📊 ตัวอย่าง Output

### หน้าจอสแกน

```text
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

```text
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

| รายการใน Summary | ความหมาย |
| :--- | :--- |
| `Suppressed (Authenticode)` | ไฟล์ที่มี Valid Digital Signature ปลอดภัย จึงถูกซ่อนผลลัพธ์ |
| `Warnings (Unverified Pub)` | ไฟล์ที่ `CompanyName` ตรงกับ Trusted List แต่ไม่มี Signature (ควรตรวจสอบเพิ่มเติม) |
| `Suppressed (VT: 0 det.)` | ไฟล์ที่ VirusTotal ยืนยันผลการตรวจเป็น 0 (ต้องเปิดใช้งาน VT API Key) |

---

## 📚 คู่มือการจัดการฐานข้อมูล (Database)

โปรแกรมรองรับ **5 วิธี** ในการเพิ่มข้อมูลลายเซ็นมัลแวร์เข้าสู่ `signatures.db`:

| วิธี | ข้อมูลที่ต้องใช้ | เหมาะสำหรับ |
| :--- | :--- | :--- |
| **1. Import CSV** ⭐ | ชื่อ + ssdeep hash (CSV) | การนำเข้าแบบคราวละมากๆ จาก Excel / Spreadsheet |
| **2. Import JSON** | ชื่อ + ssdeep hash (JSON) | นำเข้าจาก Threat Intelligence Feeds |
| **3. Import SQL** | SQL Dump File | การย้ายฐานข้อมูลเดิมจากระบบอื่น |
| **4. VT Import** | SHA256 / SHA1 + ชื่อ | มีแค่ File Hash แต่ไม่มีไฟล์มัลแวร์จริง |
| **5. Add Signature** | ssdeep full hash + ชื่อ | การเพิ่มลายเซ็นทีละรายการด้วยตนเอง |

---

### 1️⃣ Import จากไฟล์ CSV

**รูปแบบ CSV ที่รองรับ:**

*แบบ 3 คอลัมน์ (มี Family):*
```csv
name,family,ssdeep
Trojan.Generic,Backdoor,768:abc123:def456
Worm.Conficker,Worm,384:xyz789:uvw012
```

*แบบ 2 คอลัมน์ (ไม่มี Family):*
```csv
name,ssdeep
Trojan.Generic,768:abc123:def456
Worm.Conficker,384:xyz789:uvw012
```

**วิธีใช้งาน:**
```bash
scanner.exe -import C:\signatures.csv
# หรือเลือกจากเมนู Interactive: [4] -> [a]
```

---

### 2️⃣ Import จากไฟล์ JSON

```json
[
  {
    "name": "Trojan.Generic",
    "family": "Backdoor",
    "ssdeep": "768:abc123xyz:def456uvw"
  }
]
```

**วิธีใช้งาน:**
```bash
scanner.exe -import signatures.json
```

---

### 3️⃣ Import จากไฟล์ SQL

```sql
INSERT INTO `malware_signatures` VALUES ('Trojan.Generic', 'Backdoor', '768:abc123:def456');
```

**วิธีใช้งาน:**
```bash
scanner.exe -import malware_db.sql
```

---

### 4️⃣ ดึงจาก VirusTotal ด้วย SHA256 / SHA1

> ⚠️ **ข้อควรระวัง:** ต้องสร้างและใส่ API Key ในไฟล์ `vt_keys.txt` ก่อนใช้งาน

```bash
scanner.exe --vt-import "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" "Trojan.EICAR"
# หรือเลือกจากเมนู Interactive: [4] -> [b]
```

---

### 5️⃣ เพิ่มทีละรายการด้วย ssdeep Hash โดยตรง

```bash
scanner.exe --add-sig "Trojan.Generic" "768:abc123xyz:def456uvw"
```

---

## 🔑 การตั้งค่า VirusTotal (VT API)

1. ลงทะเบียนและรับ API Key จาก [VirusTotal](https://www.virustotal.com)
2. สร้างไฟล์ `vt_keys.txt` ให้อยู่ในโฟลเดอร์เดียวกับ `scanner.exe`
3. เพิ่ม Key ลงในไฟล์ (บรรทัดที่ขึ้นต้นด้วย `#` จะถือเป็นคอมเมนต์):

```txt
# vt_keys.txt - สามารถใส่ได้หลาย Keys (ระบบจะ Round-robin ให้อัตโนมัติ)
your_api_key_1_here
your_api_key_2_here
```

---

## 🛠️ ตัวอย่างการปรับแต่งการทำงาน

### 🎯 การปรับค่า Threshold Score
```text
Enter new Threshold score (0-100): 75
[+] Successfully changed Threshold to: 75
```
> *ช่วงที่แนะนำคือ **65% - 95%** (ค่าเริ่มต้นคือ 85%)*

### 📄 การกำหนด Extension
```text
Type 'all' to scan all predefined script/executable extensions > .exe, .dll, .so
[+] Scanner will EXACTLY and ONLY scan: .exe, .dll, .so
[*] Previous scan results have been reset.
```

### 🧹 การลบ Cache Database
```text
Please select an option (1-9) > 8
[+] Successfully deleted cache.db
```

---

## 📂 โครงสร้างโปรเจกต์

```text
ssdeep-scanner/
├── main.go                # Entry point, เมนูหลัก, CLI Flags Processing
├── scanner.go             # ระบบสแกนหลัก (Worker Pool + 4-Layer Logic)
├── db.go                  # จัดการ SQLite (signatures.db, cache.db)
├── import.go / export.go  # นำเข้าและส่งออกฐานข้อมูลลายเซ็นมัลแวร์
├── vt.go                  # ระบบเชื่อมต่อและสื่อสารกับ VirusTotal API
├── trusted.go             # ระบบตรวจสอบ Authenticode และ Publisher
├── trusted_windows.go     # [Windows] ตรวจ WinVerifyTrust & PE Version Info
├── trusted_other.go       # โหลดรายชื่อ Trusted Publishers จาก embedded/file
├── trusted_publishers.txt # รายชื่อ Publisher ที่เชื่อถือได้ (ผู้ใช้เพิ่มเองได้)
├── malware_model.bin      # โมเดล ML (XGBoost) สำหรับคัดกรองความน่าจะเป็น
├── signatures.db          # ฐานข้อมูล ssdeep signatures ที่ใช้อ้างอิง
├── vt_keys.txt            # ไฟล์จัดเก็บ VirusTotal API Keys
└── README.md              # เอกสารคู่มือการใช้งาน
```

---

## 🏛️ Trusted Publishers & Database Files

### การจัดการ False Positive ด้วย `trusted_publishers.txt`
โปรแกรมมีรายชื่อฝังในตัว เช่น Microsoft, Python, Node.js, Git, Oracle หากต้องการเพิ่มบริษัทอื่น ให้เพิ่มชื่อลงใน `trusted_publishers.txt`:

```txt
# ใช้ระบบ Partial match, Case-insensitive
microsoft corporation
python software foundation
my custom company name
```

### รายละเอียดไฟล์ฐานข้อมูล SQLite

| ชื่อไฟล์ | คำอธิบาย |
| :--- | :--- |
| `signatures.db` | เก็บ ssdeep signatures (`malware_name`, `block_size`, `ssdeep_full`) |
| `cache.db` | เก็บ Path และ Modified Time (`mtime`) ของไฟล์ที่เคยสแกนแล้ว เพื่อเพิ่มความเร็ว |

---

## ⚠️ ใบอนุญาตและข้อจำกัดความรับผิดชอบ

1. โปรเจกต์นี้พัฒนาขึ้นเพื่อ **การศึกษาและการวิเคราะห์เชิงพฤติกรรม (Heuristic Analysis)** เท่านั้น
2. การใช้งาน VirusTotal API จะต้องปฏิบัติตาม **Terms of Service** ของผู้ให้บริการ VirusTotal
3. ระบบ Publisher Check เป็นเพียงตัวช่วยกรองเบื้องต้น ไม่สามารถรับรองความปลอดภัยได้ 100% หากไฟล์นั้นขาด Valid Authenticode Signature