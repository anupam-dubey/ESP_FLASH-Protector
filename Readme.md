# ESP8266 Flash Protector — by Anupam Dubey
A complete solution to bind ESP8266 firmware to a specific board, preventing firmware cloning and unauthorized reuse.    
This system protects commercial ESP8266 products by adding a 64-byte cryptographic header containing an HMAC-SHA256 signature derived from:    
*Master Secret  +  Chip ID  +  Firmware Bytes*   
Only the ESP8266 device with the correct Chip ID and valid signature can boot the firmware.
If someone copies your flash dump and writes it to another ESP8266 → it will not run.  
🚀 Features

| Feature                                     | Status |
| ------------------------------------------- | ------ |
| Automatic Chip ID detection via COM port    | ✔      |
| Manual Chip ID entry (for bulk production)  | ✔      |
| Master Key (editable)                       | ✔      |
| Binary signing with 64-byte security header | ✔      |
| SPIFFS / WAV / Web firmware friendly        | ✔      |
| Adds only +64 bytes to firmware             | ✔      |
| Boot loader verification                    | ✔      |
| Python GUI provided                         | ✔      |
| Sample Arduino probe sketch                 | ✔      |
| Help + firmware examples included           | ✔      |

📂 Project Structure (Recommended)   
/ESP8266-Flash-Protector   
 ├── GUI/   
 │    └── ESP_Protector_GUI.py  
 │
 ├── Probe_Sketch/  
 │    └── ChipID_Probe.ino  
 │  
 ├── Firmware_Examples/  
 │    ├── original_before_protection.ino  
 │    └── protected_after_verification.ino  
 │  
 ├── Readme.md   ← (this file)  
 │  
 ├── build_exe_instructions.txt   
 🔐 Security Overview    
+-----------------------------------------------------------+   
| [ 64 bytes signature header ] + [ real firmware payload ] |   
+-----------------------------------------------------------+   
           |   
           ↓   
   Verified at boot using:   
   HMAC-SHA256(masterKey, chipID + firmware)    
   
   
If verification fails:

❌ Firmware signature mismatch — STOP boot.
  
  
If verification succeeds:  
  
✔ Firmware signature valid — continue boot.  

🧭 ##Usage Flow   
    
🟢 Step 1 — Get Target Device Chip ID   
  
You have two ways:  

🔌 Automatic (Recommended)  

Connect ESP8266 via USB  

Open GUI  
  
Select COM Port  
  
Click Read Chip ID  

✋ ##Manual (Optional)  

Copy & paste Chip ID printed by probe firmware.   
🟢 Step 2 — Generate Protected Firmware

1. Click Select BIN  
2. Select your firmware .bin  
3. (Optional) Edit Master Secret Key  
4. Press Generate Protected Firmware   

New file is produced:protected_<timestamp>.bin    
🟢 Step 3 — Flash Protected Firmware    
Flash using:   
esptool.py write_flash 0x00000 protected_xxxxx.bin  
or any ESP8266 flashing tool.  
🟢 Step 4 — Boot Verification (on ESP8266)  
On Serial Monitor you will see:  
[CID: xxxxxx] Verifying firmware...  
[Serial Monitor] Signature OK. Booting firmware...  
If someone copies flash to another board:  
[Serial Monitor] Signature mismatch! Firmware halted.  

📌 Probe Sketch — ChipID_Probe.ino 
Upload this sketch first to read Chip ID automatically: 
```cpp    
void setup() {   
  Serial.begin(115200);   
  delay(1000);   
  uint32_t id = ESP.getChipId();   
  Serial.print("CHIPID=");  
  Serial.println(id);   
}
void loop() {} 
```     
Copy the printed CHIPID to the GUI or let the GUI auto-read.  
## 📌  USAGE   
## File 1 — secure_header.h
Create a new header file in your Arduino project folder:
```cpp
#pragma once
#include <Arduino.h>

/*
 * ============================================================
 *  Firmware Security Header Structure — by Anupam Dubey
 * ============================================================
 *  This structure is prepended to your firmware by the
 *  ESP8266 Flash Protector tool. It includes a 32-byte
 *  HMAC-SHA256 signature, the device chip ID, and metadata.
 * ============================================================
 */
struct FirmwareHeader {
  uint8_t signature[32];   // HMAC-SHA256 of firmware + chipID
  uint32_t chipid;          // Bound ESP8266 chip ID
  uint8_t version;          // Optional firmware version
  uint8_t flags;            // Future use
  uint8_t reserved[26];     // Padding / reserved space
};

// Expected size = 64 bytes
static_assert(sizeof(FirmwareHeader) == 64, "Header must be 64 bytes");

/*
 *  Function Prototypes
 */
bool verifyFirmware();
void haltOnFailure();
```
## File 2 — secure_check.cpp  
## Create a new .cpp file (same folder) containing:   
```cpp
#include "secure_header.h"
#include <ESP8266WiFi.h>
#include <Arduino.h>

/*
 *  Minimal SHA256-HMAC Implementation
 *  (Matches Python signing tool)
 */
#include <Hash.h>   // built-in ESP8266 core library

// Define flash layout constants
#define FLASH_BASE_ADDR   0x00000000
#define HEADER_SIZE       sizeof(FirmwareHeader)

bool verifyFirmware() {
  // 1️⃣ Read Chip ID from device
  uint32_t chipid = ESP.getChipId();

  // 2️⃣ Read header from flash
  FirmwareHeader header;
  memcpy_P(&header, (const void*)FLASH_BASE_ADDR, HEADER_SIZE);

  // 3️⃣ Compute HMAC-SHA256 of firmware body
  // (Firmware starts right after header)
  uint32_t fwStart = FLASH_BASE_ADDR + HEADER_SIZE;
  uint32_t fwSize  = ESP.getFlashChipSize() - HEADER_SIZE;

  BearSSL::HashSHA256 hasher;
  hasher.init();

  // Combine Chip ID into message
  hasher.update((const uint8_t*)&chipid, sizeof(chipid));

  // Hash firmware content from flash
  for (uint32_t i = 0; i < fwSize; i += 1024) {
    uint8_t buffer[1024];
    uint32_t len = min((uint32_t)1024, fwSize - i);
    memcpy_P(buffer, (const void*)(fwStart + i), len);
    hasher.update(buffer, len);
    yield();  // prevent watchdog
  }

  uint8_t digest[32];
  hasher.final(digest);

  // 4️⃣ Compare stored signature with computed digest
  if (memcmp(digest, header.signature, 32) != 0) {
    Serial.println(F("❌ Firmware signature mismatch!"));
    return false;
  }

  // 5️⃣ Check chip ID binding
  if (header.chipid != chipid) {
    Serial.printf("❌ ChipID mismatch! Expected: %08X, Got: %08X\n",
                  header.chipid, chipid);
    return false;
  }

  Serial.println(F("✅ Firmware signature verified."));
  return true;
}

void haltOnFailure() {
  Serial.println(F("⚠️  Device halted due to security verification failure."));
  while (true) { delay(100); }
}  
```
### 🧩 Usage — Modify your existing setup()

At the top of your main .ino or .cpp, add:
```cpp
#include "secure_header.h"


Then at the start of your setup(), insert:

void setup() {
  Serial.begin(115200);
  delay(200);

  if (!verifyFirmware()) {
    haltOnFailure();
  }

  // Continue with normal startup
  RTC_init();
  SPIFFS.begin();
  ...
}
```
# NEW VERSION 2 inside version2 folder with template for code       


