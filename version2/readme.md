# 🔐 ESP8266 Flash Protection & Device Authorization System

## 📘 Introduction

Microcontrollers such as the **ESP8266** are widely adopted in low-cost IoT and industrial products due to their compact size, low power consumption, and integrated Wi-Fi capability. Despite their popularity, these devices lack essential hardware security mechanisms such as secure boot, flash encryption, and protected key storage.

As a result, firmware cloning and unauthorized duplication of products become serious concerns in real-world deployments, especially in commercial and industrial IoT systems.

This project presents a **lightweight flash protection and device authorization mechanism** designed specifically for ESP8266-class microcontrollers, where memory, computation power, and hardware security support are extremely limited.---

## 🎯 Project Objectives

- Prevent firmware cloning across ESP8266 devices  
- Bind firmware permanently to a physical chip  
- Avoid heavy cryptographic libraries  
- Use minimal ROM and RAM  
- Avoid storing secret keys in flash  
- Provide a practical provisioning workflow  

---

## 🔍 Core Concept

Instead of traditional encryption-based security, this system uses:

- ESP8266 **Chip ID**
- Device **MAC Address**
- Deterministic **bit-manipulation techniques**
- One-time **authorization fingerprint**

Once authorized, firmware copied to another ESP8266 will fail to run.

---

## 🧠 Security Philosophy

ESP8266 lacks:

- Secure element
- Secure boot
- Hardware key storage
- Flash encryption

Therefore, this system adopts a **software-only secure boot gate**, suitable for:

- Low-cost IoT devices
- Industrial displays
- Smart clocks
- Consumer electronics
- Educational and research systems

---

## 🔁 HOW TO USE
### First Boot (Unauthorized)

1. ESP boots
2. Generates device challenge
3. Sends challenge over serial
4. Waits for authorization   
CHALLENGE:xxxxxxxxxxxxxxxx   
WAITING FOR AUTHORIZATION   

---

### Authorization Step

1. Python tool reads challenge
2. Applies same transformation algorithm
3. Sends response to ESP
4. ESP verifies response
5. Device fingerprint is generated
6. Fingerprint is stored in flash
7. ESP restarts automatically

---

### Subsequent Boots

1. ESP recomputes device fingerprint
2. Compares with stored fingerprint
3. If match → main application starts
4. If mismatch → authorization mode enabled again

Firmware copied to another ESP8266 will fail verification.

FIRMWARE FLOW

setup()
 ├─ check fingerprint
 ├─ if unauthorized → wait for authorization
 └─ start main application

loop()
 └─ normal firmware operation

============================================================

### SCREEN 2 — USAGE INSTRUCTIONS
============================================================

------------------------------------------------------------

## STEP 1 — ERASE FLASH (RECOMMENDED)

Before testing, erase full flash:

esptool.py --port COM4 erase_flash

This clears:
• Firmware
• SPIFFS
• EEPROM
• Authorization fingerprint

------------------------------------------------------------

## STEP 2 — UPLOAD FIRMWARE

Upload ESP8266 firmware using:

• Arduino IDE
• PlatformIO (VS Code)

------------------------------------------------------------

## STEP 3 — POWER DEVICE

After boot, ESP will show:

CHALLENGE:xxxxxxxxxxxxxxxx
WAITING FOR AUTHORIZATION

------------------------------------------------------------

## STEP 4 — RUN PYTHON TOOL

Start the provisioning tool:

python esp8266_flash_protector.py

------------------------------------------------------------

## STEP 5 — AUTHORIZE DEVICE

• Select COM port
• Click Connect
• Challenge appears in window
• Click Authorize

------------------------------------------------------------

## STEP 6 — DEVICE RESPONSE

ESP output:

AUTHORIZED — REBOOTING
AUTHORIZED — RUNNING APPLICATION

The device is now permanently unlocked.

------------------------------------------------------------

## RE-AUTHORIZATION

To reset authorization:

esptool.py --port COM4 erase_flash

Then repeat authorization steps.

------------------------------------------------------------

## IMPORTANT NOTES

• Only one program can access COM port at a time
• Close Arduino Serial Monitor before running Python tool
• Authorization persists until flash erase

------------------------------------------------------------

## FINAL RESULT

• Firmware cannot be cloned
• Flash copy becomes useless
• Device is permanently bound
• No secrets stored
• Very low memory overhead

============================================================




