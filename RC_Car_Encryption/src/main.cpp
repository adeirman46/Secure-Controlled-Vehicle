#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include "../lib/crypto_aead.h"
#include "../lib/api.h"
#include "../lib/Xoodyak.h"
#include <string.h>
#include <iostream>

using namespace std;
#if !defined(CRYPTO_KEYBYTES)
#define CRYPTO_KEYBYTES 16
#endif
#if !defined(CRYPTO_NPUBBYTES)
#define CRYPTO_NPUBBYTES 16
#endif

#define TAGLEN 16

const char *ssid = "Irman";
const char *password = "kepanjanganhcl";
const char *mqtt_server = "broker.mqtt-dashboard.com";
const char *pub_topic = "pub_esp32";
const char *sub_topic = "sub_esp32";
unsigned char plaintext[10000]; // Updated to accommodate larger input
unsigned char ciphertext[10000 + TAGLEN];
unsigned char decryptedtext[10000]; // Updated to accommodate larger input
unsigned long long plaintext_len;
unsigned long long ciphertext_len;

// Key and nonce for encryption and decryption
unsigned char key[CRYPTO_KEYBYTES] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
unsigned char nonce[CRYPTO_NPUBBYTES] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE (50)
char subscribedMsg[MSG_BUFFER_SIZE];
char msg[MSG_BUFFER_SIZE];
int value = 0;

// Set web server port number to 80
WiFiServer server(80);

// Variable to store the HTTP request
String header;

// // Motor 1
// int motor1Pin1 = 12;
// int motor1Pin2 = 14;
// int enable1Pin = 13;

// // Motor 2
// int motor2Pin1 = 27;
// int motor2Pin2 = 26;
// int enable2Pin = 25;

// // Setting PWM properties
// const int freq = 60000;
// const int pwmChannel = 0;
// const int resolution = 8;
int dutyCycle = 0;

// Decode HTTP GET value
String valueString = String(5);
int pos1 = 0;
int pos2 = 0;

// Current time
unsigned long currentTime = millis();
// Previous time
unsigned long previousTime = 0;
// Define timeout time in milliseconds (example: 2000ms = 2s)
const long timeoutTime = 2000;

int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
  Xoodyak instance(BitString(k, 8 * CRYPTO_KEYBYTES), BitString(npub, 8 * CRYPTO_NPUBBYTES), BitString());

  (void)nsec;

  instance.Absorb(BitString(ad, 8 * (size_t)adlen));
  BitString cryptString = instance.Encrypt(BitString(m, 8 * (size_t)mlen));
  if (cryptString.size() != 0)
    std::copy(cryptString.array(), cryptString.array() + (cryptString.size() + 7) / 8, c);
  BitString tagString = instance.Squeeze(TAGLEN);
  if (tagString.size() != 0)
    std::copy(tagString.array(), tagString.array() + (tagString.size() + 7) / 8, c + mlen);
  *clen = mlen + TAGLEN;
#if 0
	{
		unsigned int i;
		for (i = 0; i < *clen; ++i )
		{
			printf("\\x%02x", c[i] );
		}
		printf("\n");
	}
#endif
  return 0;
}

WiFiClient espClient;
PubSubClient mqtt_client(espClient);

void reconnect()
{
  // Loop until we're reconnected
  while (!mqtt_client.connected())
  {
    Serial.print("Attempting MQTT connection...");
    // Create a random client ID
    String clientId = "ESP32Client-";
    clientId += String(random(0xffff), HEX);
    // Attempt to connect
    if (mqtt_client.connect(clientId.c_str()))
    {
      Serial.println("connected");
      // Once connected, publish an announcement...
      mqtt_client.publish(pub_topic, "hello world - esp32 connected");
      // ... and resubscribe
      mqtt_client.subscribe(sub_topic);
    }
    else
    {
      Serial.print("failed, rc=");
      Serial.print(mqtt_client.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void loop()
{
  WiFiClient client = server.available(); // Listen for incoming clients
  if (!mqtt_client.connected())
  {
    reconnect();
  }
  mqtt_client.loop();

  if (client)
  { // If a new client connects,
    currentTime = millis();
    previousTime = currentTime;
    Serial.println("New Client."); // print a message out in the serial port
    String currentLine = "";       // make a String to hold incoming data from the client
    while (client.connected() && currentTime - previousTime <= timeoutTime)
    { // loop while the client's connected
      currentTime = millis();
      if (client.available())
      {                         // if there's bytes to read from the client,
        char c = client.read(); // read a byte, then
        Serial.write(c);        // print it out the serial monitor
        header += c;
        if (c == '\n')
        { // if the byte is a newline character
          // if the current line is blank, you got two newline characters in a row.
          // that's the end of the client HTTP request, so send a response:
          if (currentLine.length() == 0)
          {
            // HTTP headers always start with a response code (e.g. HTTP/1.1 200 OK)
            // and a content-type so the client knows what's coming, then a blank line:
            client.println("HTTP/1.1 200 OK");
            client.println("Content-type:text/html");
            client.println("Connection: close");
            client.println();

            // Controls the motor pins according to the button pressed
            if (header.indexOf("GET /forward") >= 0)
            {
              String message = "forward";
              Serial.println(message);
              // digitalWrite(motor1Pin1, LOW);
              // digitalWrite(motor1Pin2, HIGH);
              // digitalWrite(motor2Pin1, LOW);
              // digitalWrite(motor2Pin2, HIGH);

              // Encrypt the message
              crypto_aead_encrypt(ciphertext, &ciphertext_len, (const unsigned char *)message.c_str(), message.length(), NULL, 0, NULL, nonce, key);

              // Print the ciphertext
              Serial.print("Ciphertext: ");
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
                Serial.printf("%02X", ciphertext[i]);
              }
              Serial.println("");

              // Publish the ciphertext
              // Create a buffer to store the hexadecimal representation of the ciphertext
              char hexCiphertext[ciphertext_len * 2 + 1];

              // Convert each byte of the ciphertext to a hexadecimal string
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
                sprintf(&hexCiphertext[i * 2], "%02X", ciphertext[i]);
              }

              // Null-terminate the string
              hexCiphertext[ciphertext_len * 2] = '\0';

              // Publish the ciphertext
              mqtt_client.publish(sub_topic, hexCiphertext);
            }
            
            else if (header.indexOf("GET /left") >= 0)
            {
              String message = "left";
              Serial.println(message);
              // digitalWrite(motor1Pin1, LOW);
              // digitalWrite(motor1Pin2, HIGH);
              // digitalWrite(motor2Pin1, LOW);
              // digitalWrite(motor2Pin2, LOW);
              // Encrypt the message
              crypto_aead_encrypt(ciphertext, &ciphertext_len, (const unsigned char *)message.c_str(), message.length(), NULL, 0, NULL, nonce, key);

              // Print the ciphertext
              Serial.print("Ciphertext: ");
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              Serial.printf("%02X", ciphertext[i]);
              }
              Serial.println("");

              // Publish the ciphertext
              // Create a buffer to store the hexadecimal representation of the ciphertext
              char hexCiphertext[ciphertext_len * 2 + 1];

              // Convert each byte of the ciphertext to a hexadecimal string
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              sprintf(&hexCiphertext[i * 2], "%02X", ciphertext[i]);
              }

              // Null-terminate the string
              hexCiphertext[ciphertext_len * 2] = '\0';

              // Publish the ciphertext
              mqtt_client.publish(sub_topic, hexCiphertext);

            }
            else if (header.indexOf("GET /stop") >= 0)
            {
              String message = "stop";
              Serial.println(message);
              // digitalWrite(motor1Pin1, LOW);
              // digitalWrite(motor1Pin2, LOW);
              // digitalWrite(motor2Pin1, LOW);
              // digitalWrite(motor2Pin2, LOW);

              // Encrypt the message
              crypto_aead_encrypt(ciphertext, &ciphertext_len, (const unsigned char *)message.c_str(), message.length(), NULL, 0, NULL, nonce, key);

              // Print the ciphertext
              Serial.print("Ciphertext: ");
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              Serial.printf("%02X", ciphertext[i]);
              }
              Serial.println("");

              // Publish the ciphertext
              // Create a buffer to store the hexadecimal representation of the ciphertext
              char hexCiphertext[ciphertext_len * 2 + 1];

              // Convert each byte of the ciphertext to a hexadecimal string
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              sprintf(&hexCiphertext[i * 2], "%02X", ciphertext[i]);
              }

              // Null-terminate the string
              hexCiphertext[ciphertext_len * 2] = '\0';

              // Publish the ciphertext
              mqtt_client.publish(sub_topic, hexCiphertext);
            }
            else if (header.indexOf("GET /right") >= 0)
            {
              String message = "right";
              Serial.println(message);
              // digitalWrite(motor1Pin1, LOW);
              // digitalWrite(motor1Pin2, LOW);
              // digitalWrite(motor2Pin1, LOW);
              // digitalWrite(motor2Pin2, HIGH);

              // Encrypt the message
              crypto_aead_encrypt(ciphertext, &ciphertext_len, (const unsigned char *)message.c_str(), message.length(), NULL, 0, NULL, nonce, key);

              // Print the ciphertext
              Serial.print("Ciphertext: ");
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              Serial.printf("%02X", ciphertext[i]);
              }
              Serial.println("");

              // Publish the ciphertext
              // Create a buffer to store the hexadecimal representation of the ciphertext
              char hexCiphertext[ciphertext_len * 2 + 1];

              // Convert each byte of the ciphertext to a hexadecimal string
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              sprintf(&hexCiphertext[i * 2], "%02X", ciphertext[i]);
              }

              // Null-terminate the string
              hexCiphertext[ciphertext_len * 2] = '\0';

              // Publish the ciphertext
              mqtt_client.publish(sub_topic, hexCiphertext);
            }
            else if (header.indexOf("GET /reverse") >= 0)
            {
              String message = "reverse";
              Serial.println(message);
              // digitalWrite(motor1Pin1, HIGH);
              // digitalWrite(motor1Pin2, LOW);
              // digitalWrite(motor2Pin1, HIGH);
              // digitalWrite(motor2Pin2, LOW);

              // Encrypt the message
              crypto_aead_encrypt(ciphertext, &ciphertext_len, (const unsigned char *)message.c_str(), message.length(), NULL, 0, NULL, nonce, key);

              // Print the ciphertext
              Serial.print("Ciphertext: ");
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              Serial.printf("%02X", ciphertext[i]);
              }
              Serial.println("");

              // Publish the ciphertext
              // Create a buffer to store the hexadecimal representation of the ciphertext
              char hexCiphertext[ciphertext_len * 2 + 1];

              // Convert each byte of the ciphertext to a hexadecimal string
              for (unsigned long long i = 0; i < ciphertext_len; i++)
              {
              sprintf(&hexCiphertext[i * 2], "%02X", ciphertext[i]);
              }

              // Null-terminate the string
              hexCiphertext[ciphertext_len * 2] = '\0';

              // Publish the ciphertext
              mqtt_client.publish(sub_topic, hexCiphertext);
            }
            // Display the HTML web page
            client.println("<!DOCTYPE HTML><html>");
            client.println("<head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            client.println("<link rel=\"icon\" href=\"data:,\">");
            // CSS to style the buttons and center the content
            client.println("<style>html, body { height: 100%; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; }");
            client.println(".container { display: flex; flex-direction: column; align-items: center; justify-content: center; }");
            client.println(".button { -webkit-user-select: none; -moz-user-select: none; -ms-user-select: none; user-select: none; background-color: #ad2218;");
            client.println("border: none; color: white; padding: 12px 28px; text-decoration: none; font-size: 26px; margin: 1px; cursor: pointer;}");
            client.println(".button2 {background-color: #555555;}");
            client.println(".small-button { -webkit-user-select: none; -moz-user-select: none; -ms-user-select: none; user-select: none; background-color: #ad2218;");
            client.println("border: none; color: white; padding: 8px 16px; text-decoration: none; font-size: 18px; margin: 1px; cursor: pointer;}");
            client.println("</style>");
            client.println("<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js\"></script></head>");

            // Web Page
            client.println("<body>");
            client.println("<div class=\"container\">");
            client.println("<p><button class=\"button\" onclick=\"moveForward()\">FORWARD</button></p>");
            client.println("<p><button class=\"button\" onclick=\"moveLeft()\">LEFT</button>");
            client.println("<button class=\"button button2\" onclick=\"stopRobot()\">STOP</button>");
            client.println("<button class=\"button\" onclick=\"moveRight()\">RIGHT</button></p>");
            client.println("<p><button class=\"button\" onclick=\"moveReverse()\">REVERSE</button></p>");
            client.println("<p>Motor Speed: <span id=\"motorSpeed\"></span></p>");
            client.println("<input type=\"range\" min=\"0\" max=\"100\" step=\"25\" id=\"motorSlider\" onchange=\"motorSpeed(this.value)\" value=\"" + valueString + "\"/>");
            client.println("<p>Password: <input type=\"password\" id=\"password\"></p>");
            client.println("<p><button class=\"small-button\" onclick=\"checkPassword()\">Submit</button></p>");
            client.println("</div>");

            client.println("<script>");
            client.println("function checkPassword() {");
            client.println("  var password = document.getElementById(\"password\").value;");
            client.println("  if (password === \"3.14159265\") {");
            client.println("    document.getElementById(\"password\").disabled = true;");
            client.println("    document.getElementById(\"password\").style.backgroundColor = \"#169e18\";");
            client.println("    enableControls();");
            client.println("  } else {");
            client.println("    document.getElementById(\"password\").style.backgroundColor = \"#ad2218\";");
            client.println("    disableControls();");
            client.println("  }");
            client.println("}");
            client.println("function enableControls() {");
            client.println("  var buttons = document.getElementsByClassName(\"button\");");
            client.println("  for (var i = 0; i < buttons.length; i++) {");
            client.println("    buttons[i].style.backgroundColor = \"#169e18\";");
            client.println("  }");
            client.println("  var slider = document.getElementById(\"motorSlider\");");
            client.println("  slider.disabled = false;");
            client.println("}");
            client.println("function disableControls() {");
            client.println("  var buttons = document.getElementsByClassName(\"button\");");
            client.println("  for (var i = 0; i < buttons.length; i++) {");
            client.println("    buttons[i].style.backgroundColor = \"#ad2218\";");
            client.println("  }");
            client.println("  var slider = document.getElementById(\"motorSlider\");");
            client.println("  slider.disabled = true;");
            client.println("}");
            client.println("function moveForward() { if (!document.getElementById(\"password\").disabled) return; $.get(\"/forward\"); {Connection: close};}");
            client.println("function moveLeft() { if (!document.getElementById(\"password\").disabled) return; $.get(\"/left\"); {Connection: close};}");
            client.println("function stopRobot() { if (!document.getElementById(\"password\").disabled) return; $.get(\"/stop\"); {Connection: close};}");
            client.println("function moveRight() { if (!document.getElementById(\"password\").disabled) return; $.get(\"/right\"); {Connection: close};}");
            client.println("function moveReverse() { if (!document.getElementById(\"password\").disabled) return; $.get(\"/reverse\"); {Connection: close};}");
            client.println("var slider = document.getElementById(\"motorSlider\");");
            client.println("var motorP = document.getElementById(\"motorSpeed\"); motorP.innerHTML = slider.value;");
            client.println("slider.oninput = function() { slider.value = this.value; motorP.innerHTML = this.value; }");
            client.println("function motorSpeed(pos) { if (!document.getElementById(\"password\").disabled) return; $.get(\"/?value=\" + pos + \"&\"); {Connection: close};}</script>");

            client.println("</body></html>");

            // Request example: GET /?value=100& HTTP/1.1 - sets PWM duty cycle to 100% = 255
            if (header.indexOf("GET /?value=") >= 0)
            {
              pos1 = header.indexOf('=');
              pos2 = header.indexOf('&');
              valueString = header.substring(pos1 + 1, pos2);
              // Set motor speed value
              if (valueString == "0")
              {
                // ledcWrite(pwmChannel, 0);
                // digitalWrite(motor1Pin1, LOW);
                // digitalWrite(motor1Pin2, LOW);
                // digitalWrite(motor2Pin1, LOW);
                // digitalWrite(motor2Pin2, LOW);
                String message = "0";
                Serial.println(message);
                // Encrypt the message
                crypto_aead_encrypt(ciphertext, &ciphertext_len, (const unsigned char *)message.c_str(), message.length(), NULL, 0, NULL, nonce, key);

                // Print the ciphertext
                Serial.print("Ciphertext: ");
                for (unsigned long long i = 0; i < ciphertext_len; i++)
                {
                Serial.printf("%02X", ciphertext[i]);
                }
                Serial.println("");

                // Publish the ciphertext
                // Create a buffer to store the hexadecimal representation of the ciphertext
                char hexCiphertext[ciphertext_len * 2 + 1];

                // Convert each byte of the ciphertext to a hexadecimal string
                for (unsigned long long i = 0; i < ciphertext_len; i++)
                {
                sprintf(&hexCiphertext[i * 2], "%02X", ciphertext[i]);
                }

                // Null-terminate the string
                hexCiphertext[ciphertext_len * 2] = '\0';

                // Publish the ciphertext
                mqtt_client.publish(sub_topic, hexCiphertext);
              }
              else
              {
                dutyCycle = map(valueString.toInt(), 25, 100, 200, 255);
                // ledcWrite(pwmChannel, dutyCycle);
                String message = valueString;
                Serial.println(message);

                // Encrypt the message
                crypto_aead_encrypt(ciphertext, &ciphertext_len, (const unsigned char *)message.c_str(), message.length(), NULL, 0, NULL, nonce, key);

                // Print the ciphertext
                Serial.print("Ciphertext: ");
                for (unsigned long long i = 0; i < ciphertext_len; i++)
                {
                Serial.printf("%02X", ciphertext[i]);
                }
                Serial.println("");

                // Publish the ciphertext
                // Create a buffer to store the hexadecimal representation of the ciphertext
                char hexCiphertext[ciphertext_len * 2 + 1];

                // Convert each byte of the ciphertext to a hexadecimal string
                for (unsigned long long i = 0; i < ciphertext_len; i++)
                {
                sprintf(&hexCiphertext[i * 2], "%02X", ciphertext[i]);
                }

                // Null-terminate the string
                hexCiphertext[ciphertext_len * 2] = '\0';

                // Publish the ciphertext
                mqtt_client.publish(sub_topic, hexCiphertext);
              }
            }
            // The HTTP response ends with another blank line
            client.println();
            // Break out of the while loop
            break;
          }
          else
          { // if you got a newline, then clear currentLine
            currentLine = "";
          }
        }
        else if (c != '\r')
        {                   // if you got anything else but a carriage return character,
          currentLine += c; // add it to the end of the currentLine
        }
      }
    }
    // Clear the header variable
    header = "";
    // Close the connection
    client.stop();
  }
}
void setup()
{
  Serial.begin(115200);

  // // Set the Motor pins as outputs
  // pinMode(motor1Pin1, OUTPUT);
  // pinMode(motor1Pin2, OUTPUT);
  // pinMode(motor2Pin1, OUTPUT);
  // pinMode(motor2Pin2, OUTPUT);

  // // Configure PWM channel functionalities
  // ledcSetup(pwmChannel, freq, resolution);

  // // Attach the PWM channel 0 to the enable pins which are the GPIOs to be controlled
  // ledcAttachPin(enable1Pin, pwmChannel);
  // ledcAttachPin(enable2Pin, pwmChannel);

  // // Produce a PWM signal to both enable pins with a duty cycle 0
  // ledcWrite(pwmChannel, dutyCycle);

  // Connect to Wi-Fi network with SSID and password
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }
  // Print local IP address and start web server
  Serial.println("");
  Serial.println("WiFi connected.");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
  server.begin();

  mqtt_client.setServer(mqtt_server, 1883);

}
