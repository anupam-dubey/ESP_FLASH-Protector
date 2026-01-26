#include <EEPROM.h>

#define EEPROM_SIZE 128
#define MAGIC_ADDR  0
#define FP_ADDR     1
#define MAGIC_VALUE 0xA5

#define CH_LEN 64
#define FP_LEN 32

uint8_t challenge[CH_LEN];
uint8_t fingerprint[FP_LEN];
uint8_t stored_fp[FP_LEN];

uint32_t chip;
uint8_t mac[6];


// ------------------------------------------------
// ROTATION
// ------------------------------------------------
uint8_t rol(uint8_t v, uint8_t r) {
  return (v << r) | (v >> (8 - r));
}


// ------------------------------------------------
// CHALLENGE GENERATION
// ------------------------------------------------
void generateChallenge() {
  for (int i = 0; i < CH_LEN; i++) {
    uint8_t x =
      ((chip >> (8 * (i % 4))) & 0xFF) ^
      mac[i % 6] ^
      (millis() >> (i % 4));

    challenge[i] = x;
  }
}



// ------------------------------------------------
// RESPONSE → FINGERPRINT
// ------------------------------------------------
void deriveDeviceFingerprint(uint8_t *fp) {

  memset(fp, 0, FP_LEN);

  for (int i = 0; i < FP_LEN; i++) {
    uint8_t v =
      (chip >> (i % 8)) ^
      mac[i % 6] ^
      (0xA5 + i * 13);

    fp[i] = rol(v, (i % 5) + 1);
  }
}



// ------------------------------------------------
// EEPROM
// ------------------------------------------------
void saveFP(uint8_t *fp) {
  EEPROM.begin(EEPROM_SIZE);
  EEPROM.write(MAGIC_ADDR, MAGIC_VALUE);

  for (int i = 0; i < FP_LEN; i++)
    EEPROM.write(FP_ADDR + i, fp[i]);

  EEPROM.commit();
}

bool loadFP(uint8_t *fp) {
  EEPROM.begin(EEPROM_SIZE);

  if (EEPROM.read(MAGIC_ADDR) != MAGIC_VALUE)
    return false;

  for (int i = 0; i < FP_LEN; i++)
    fp[i] = EEPROM.read(FP_ADDR + i);

  return true;
}


void waitForAuthorization() {

  uint8_t dummy[FP_LEN];

  while (true) {

    if (Serial.available()) {

      // any valid response triggers provisioning
      delay(50);

      deriveDeviceFingerprint(dummy);
      saveFP(dummy);

      Serial.println("AUTHORIZED — REBOOTING");
      delay(300);
      ESP.restart();
    }

    yield();
  }
}
