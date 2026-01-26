#include <Arduino.h>

#include "challenge.h"


void startApplication() {
	
	// your main code goes here for setup initialise
	
 
}




void setup() {

 

  Serial.begin(115200);
  delay(10);

  chip = ESP.getChipId();
  WiFi.macAddress(mac);

  generateChallenge();

  bool authorized = false;

  if (loadFP(stored_fp)) {
    deriveDeviceFingerprint(fingerprint);
    if (memcmp(stored_fp, fingerprint, FP_LEN) == 0) {
      authorized = true;
      Serial.println("AUTHORIZED — RUNNING APPLICATION");
    }
  }

  if (!authorized) {

    Serial.print("CHALLENGE:");
    for (int i = 0; i < CH_LEN; i++) {
      if (challenge[i] < 16) Serial.print("0");
      Serial.print(challenge[i], HEX);
    }
    Serial.println();
    Serial.println("WAITING FOR AUTHORIZATION...");

    waitForAuthorization();   // blocks until restart
  }

   startApplication();
 
 
 
}


// LOOP

void loop() {
 
 if (portalActive) {

  webSocket.loop();
  server.handleClient();

  unsigned long now = millis();

  // Case 1: No client ever connected
  if ((now - portalStartTime > PORTAL_GRACE_MS) &&
      (lastClientActivity == portalStartTime)) {

    stopConfigPortal();
  }

  // Case 2: Client idle / disconnected
  if ((now - lastClientActivity) > PORTAL_IDLE_MS) {
    stopConfigPortal();
  }
  if (reminderPending) {

    reminderPending = false;
    // skip "rS,"
    handleReminderCmd(reminderCmd); 

    Serial.println("Reminder processed");
  }
  

   yield();   // <<< CRITICAL
     if (showtime(configdisp.ttype)) {    // returns true when done
      Disp.clear();
     }
   Disp.loop();
}
else  
{
disptime();
  // yield();   // <<< CRITICAL
}
}