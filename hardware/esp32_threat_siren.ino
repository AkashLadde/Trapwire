/*
 * =====================================================================================
 * TRAPWIRE — Physical Threat Siren & SOC Hardware Alarm
 * Target Board: ESP32 Dev Module / NodeMCU-32S
 * =====================================================================================
 * Pinout Connections:
 *  - 0.96" SSD1306 I2C OLED Display:
 *      VCC -> 3V3 (or VIN)
 *      GND -> GND
 *      SDA -> GPIO 21 (Pin D21)
 *      SCL -> GPIO 22 (Pin D22)
 *
 *  - Buzzer (Dual-Mode: Supports BOTH Active and Passive Buzzers):
 *      (+) / Signal -> GPIO 19 (Pin D19)
 *      (-) / GND    -> GND
 *      VCC (if 3-pin module) -> VIN (5V) or 3V3
 *
 *  - Visual Strobe:
 *      Uses NodeMCU Built-in Blue LED on GPIO 2 (Pin D2) - No external LEDs needed!
 * =====================================================================================
 */

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

#define PIN_BUZZER      19       // Pin D19 on NodeMCU ESP32
#define PIN_BUILTIN_LED 2        // Pin D2 (Built-in Blue LED on ESP32)
#define I2C_SDA         21       // Pin D21
#define I2C_SCL         22       // Pin D22

// Threat State
enum ThreatLevel { NORMAL, WARNING, CRITICAL };
ThreatLevel currentThreat = NORMAL;
String lastAlertMsg = "SYSTEM ARMED & SECURE";
String lastAttackerIp = "STANDBY";
unsigned long lastAlarmTime = 0;
bool oledFound = false;

// Dual-mode buzzer driver: drives BOTH active (digital HIGH) and passive (PWM tone) buzzers
void buzzerOn(int freq = 2400) {
  #if defined(ESP32)
  tone(PIN_BUZZER, freq);
  #endif
  digitalWrite(PIN_BUZZER, HIGH);
}

void buzzerOff() {
  #if defined(ESP32)
  noTone(PIN_BUZZER);
  #endif
  digitalWrite(PIN_BUZZER, LOW);
}

// Helper: Extract JSON string values without external dependencies
String extractJsonField(String json, String field) {
  String search = "\"" + field + "\":";
  int idx = json.indexOf(search);
  if (idx == -1) {
    search = "\"" + field + "\" :";
    idx = json.indexOf(search);
  }
  if (idx == -1) return "";
  
  int start = json.indexOf("\"", idx + search.length());
  if (start == -1) return "";
  int end = json.indexOf("\"", start + 1);
  if (end == -1) return "";
  return json.substring(start + 1, end);
}

void soundAlarmChirp() {
  for (int i = 0; i < 3; i++) {
    buzzerOn(2400 + (i * 200));
    digitalWrite(PIN_BUILTIN_LED, HIGH);
    delay(90);
    buzzerOff();
    digitalWrite(PIN_BUILTIN_LED, LOW);
    delay(40);
  }
}

void renderOled() {
  if (!oledFound) return;

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  // Inverted Header Banner
  display.fillRect(0, 0, 128, 13, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
  display.setCursor(4, 3);
  if (currentThreat == CRITICAL) {
    display.print("! TRAPWIRE BREACH !");
  } else if (currentThreat == WARNING) {
    display.print("THREAT PROBE WATCH");
  } else {
    display.print("TRAPWIRE SOC MONITOR");
  }

  display.setTextColor(SSD1306_WHITE);
  
  // Status Line
  display.setCursor(0, 16);
  display.print("STATUS: ");
  if (currentThreat == CRITICAL) display.println("CRITICAL ATTACK");
  else if (currentThreat == WARNING) display.println("PROBE / RECON");
  else display.println("ARMED & SECURE");

  // Attacker IP (Highlighted)
  display.setCursor(0, 28);
  display.print("SRC IP: ");
  display.println(lastAttackerIp);

  // Message lines (truncate cleanly to screen width)
  display.setCursor(0, 42);
  display.println(lastAlertMsg.substring(0, 21));
  display.setCursor(0, 52);
  if (lastAlertMsg.length() > 21) {
    display.println(lastAlertMsg.substring(21, 42));
  }

  display.display();
}

void parseThreatPacket(String input) {
  // Support simple manual text commands from Serial Monitor (e.g. TEST, ALARM, RESET)
  if (input.equalsIgnoreCase("TEST") || input.equalsIgnoreCase("ALARM") || input.equalsIgnoreCase("TRIGGER")) {
    currentThreat = CRITICAL;
    lastAlertMsg = "MANUAL TEST TRIGGERED";
    lastAttackerIp = "185.220.101.45";
    lastAlarmTime = millis();
    soundAlarmChirp();
    renderOled();
    Serial.println("{\"status\": \"ALARM_TRIGGERED\", \"source\": \"MANUAL_TEST\"}");
    return;
  } else if (input.equalsIgnoreCase("RESET") || input.equalsIgnoreCase("CLEAR") || input.equalsIgnoreCase("NORMAL")) {
    currentThreat = NORMAL;
    buzzerOff();
    digitalWrite(PIN_BUILTIN_LED, LOW);
    lastAlertMsg = "SYSTEM ARMED & SECURE";
    lastAttackerIp = "STANDBY";
    renderOled();
    Serial.println("{\"status\": \"SYSTEM_RESET\", \"level\": \"NORMAL\"}");
    return;
  }

  // Parse JSON format from Serial Bridge
  String level = extractJsonField(input, "level");
  String msg   = extractJsonField(input, "message");
  String ip    = extractJsonField(input, "attacker_ip");
  if (ip == "") ip = extractJsonField(input, "ip");

  if (level == "") {
    if (input.indexOf("critical") != -1 || input.indexOf("CRITICAL") != -1) level = "critical";
    else if (input.indexOf("warning") != -1 || input.indexOf("WARNING") != -1) level = "warning";
    else level = "info";
  }

  if (msg != "") lastAlertMsg = msg;
  else lastAlertMsg = "Threat event detected";

  if (ip != "") lastAttackerIp = ip;
  else lastAttackerIp = "185.220.101.45";

  lastAlarmTime = millis();

  if (level.equalsIgnoreCase("critical") || level.equalsIgnoreCase("emergency")) {
    currentThreat = CRITICAL;
    soundAlarmChirp();
  } else if (level.equalsIgnoreCase("warning")) {
    currentThreat = WARNING;
  } else {
    currentThreat = NORMAL;
  }

  renderOled();
  Serial.print("{\"ack\": true, \"threat_level\": \"");
  Serial.print(level);
  Serial.println("\"}");
}

void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(PIN_BUZZER, OUTPUT);
  buzzerOff();
  
  pinMode(PIN_BUILTIN_LED, OUTPUT);
  digitalWrite(PIN_BUILTIN_LED, LOW);

  // Initialize I2C Bus on GPIO 21 (SDA) and GPIO 22 (SCL)
  Wire.begin(I2C_SDA, I2C_SCL);

  // Initialize SSD1306 OLED (Auto-detect address 0x3C or 0x3D)
  if (display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    oledFound = true;
  } else if (display.begin(SSD1306_SWITCHCAPVCC, 0x3D)) {
    oledFound = true;
  }

  if (oledFound) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(6, 6);
    display.println("TRAPWIRE DEFENDER");
    display.setCursor(6, 22);
    display.println("ESP32 HARDWARE NODE");
    display.setCursor(6, 38);
    display.println("FIRMWARE: v2.5 ARMED");
    display.setCursor(6, 52);
    display.println("WAITING FOR SOC DATA");
    display.display();
  }

  // --- STARTUP HARDWARE SELF-TEST ---
  // 3 Short chirps & LED flashes give instant proof buzzer + LED are working
  for (int i = 0; i < 3; i++) {
    digitalWrite(PIN_BUILTIN_LED, HIGH);
    buzzerOn(2400 + (i * 200));
    delay(70);
    digitalWrite(PIN_BUILTIN_LED, LOW);
    buzzerOff();
    delay(50);
  }

  Serial.println("{\"node_id\": \"ESP32-THREAT-SIREN\", \"status\": \"READY\", \"firmware\": \"2.5.0-DUAL-MODE\", \"oled\": " + String(oledFound ? "true" : "false") + "}");
}

void loop() {
  // 1. Read incoming threat alerts from USB Serial
  if (Serial.available() > 0) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() > 0) {
      parseThreatPacket(input);
    }
  }

  // 2. Visual & Audio Alarm Handling
  if (currentThreat == CRITICAL) {
    unsigned long now = millis();
    // Rapid strobe on Built-in Blue LED & Pulsed Siren Alarm (Supports both Active and Passive buzzers)
    if ((now / 150) % 2 == 0) {
      digitalWrite(PIN_BUILTIN_LED, HIGH);
      buzzerOn(2400);
    } else {
      digitalWrite(PIN_BUILTIN_LED, LOW);
      buzzerOff();
    }
    
    // Auto-silence back to normal after 15 seconds
    if (now - lastAlarmTime > 15000) {
      currentThreat = NORMAL;
      buzzerOff();
      digitalWrite(PIN_BUILTIN_LED, LOW);
      lastAlertMsg = "SYSTEM ARMED & SECURE";
      lastAttackerIp = "STANDBY";
      renderOled();
    }
  } else if (currentThreat == WARNING) {
    buzzerOff();
    digitalWrite(PIN_BUILTIN_LED, HIGH); // Solid Blue
  } else {
    buzzerOff();
    digitalWrite(PIN_BUILTIN_LED, LOW);
  }
  
  delay(20);
}
