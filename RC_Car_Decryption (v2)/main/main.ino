#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include "crypto_aead.h"
#include "api.h"
#include "Xoodyak.h"
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

WiFiClient espClient;
PubSubClient client(espClient);

unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE (50)
char msg[MSG_BUFFER_SIZE];
int value = 0;

#if !defined(CRYPTO_KEYBYTES)
#define CRYPTO_KEYBYTES 16
#endif
#if !defined(CRYPTO_NPUBBYTES)
#define CRYPTO_NPUBBYTES 16
#endif
#define TAGLEN 16

// Motor 1
int motor1Pin1 = 12;
int motor1Pin2 = 14;
int enable1Pin = 13;

// Motor 2
int motor2Pin1 = 27;
int motor2Pin2 = 26;
int enable2Pin = 25;

// Setting PWM properties
const int freq = 30000;
const int pwmChannel = 0;
const int resolution = 8;
int dutyCycle = 0;

int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
  Xoodyak instance(BitString(k, 8 * CRYPTO_KEYBYTES), BitString(npub, 8 * CRYPTO_NPUBBYTES), BitString());
  unsigned char tag[TAGLEN];
  unsigned long long mlen_;

  (void)nsec;

  *mlen = 0;
  if (clen < TAGLEN)
  {
    return -1;
  }
  mlen_ = clen - TAGLEN;
  instance.Absorb(BitString(ad, 8 * (size_t)adlen));
  BitString decryptString = instance.Decrypt(BitString(c, 8 * (size_t)mlen_));
  if (decryptString.size() != 0)
    std::copy(decryptString.array(), decryptString.array() + (decryptString.size() + 7) / 8, m);
  BitString tagString = instance.Squeeze(TAGLEN);
  if (tagString.size() != 0)
    std::copy(tagString.array(), tagString.array() + (tagString.size() + 7) / 8, tag);
  if (memcmp(tag, c + mlen_, TAGLEN) != 0)
  {
    memset(m, 0, (size_t)mlen_);
    return -1;
  }
  *mlen = mlen_;
  return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *hexToChar(const char *hexString)
{
	size_t len = strlen(hexString);
	if (len % 2 != 0)
	{
		printf("Invalid hex string length\n");
		return NULL;
	}

	size_t charLen = len / 2;
	char *charString = (char *)malloc(charLen + 1);
	charString[charLen] = '\0';

	for (size_t i = 0, j = 0; i < len; i += 2, j++)
	{
		char byteString[3];
		strncpy(byteString, hexString + i, 2);
		byteString[2] = '\0';

		char byte = (char)strtol(byteString, NULL, 16);
		charString[j] = byte;
	}

	return charString;
}

void setup_wifi()
{

  delay(10);
  // We start by connecting to a WiFi network
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }

  randomSeed(micros());

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

#define MAX_SUBSCRIBED_MSG_SIZE 1000

char *subscribedMsg;
unsigned int subscribedMsgLength = 0;

char* decryptedtext_now = new char[strlen((char*)decryptedtext) + 1];

void callback(char *topic, byte *payload, unsigned int length) {

  if (subscribedMsg != NULL) {
    delete[] subscribedMsg;
  }
  subscribedMsg = new char[length + 1];
  
  // Copy the payload into the subscribedMsg variable
  strncpy(subscribedMsg, (char *)payload, length);
  subscribedMsg[length] = '\0'; // Add a null terminator
  subscribedMsgLength = length;

  // Print the received message
  Serial.print("Received message: ");
  Serial.println(subscribedMsg);

  char *outputText = hexToChar(subscribedMsg);
	ciphertext_len = strlen(outputText);
  strcpy((char *)ciphertext, outputText);

  // Decrypt ciphertext
  crypto_aead_decrypt(decryptedtext, &plaintext_len, NULL, ciphertext, ciphertext_len, NULL, 0, nonce, key);

  // Print the decrypted text
  Serial.printf("Decrypted: %s\n", (unsigned char*) decryptedtext);

  strcpy(decryptedtext_now, (char*)decryptedtext);
  // Clear variables
  memset(subscribedMsg, 0, sizeof(subscribedMsg));
  memset(decryptedtext, 0, sizeof(decryptedtext));
  plaintext_len = 0;
}

void reconnect()
{
  // Loop until we're reconnected
  while (!client.connected())
  {
    Serial.print("Attempting MQTT connection...");
    // Create a random client ID
    String clientId = "ESP32Client-";
    clientId += String(random(0xffff), HEX);
    // Attempt to connect
    if (client.connect(clientId.c_str()))
    {
      Serial.println("connected");
      // Once connected, publish an announcement...
      client.publish(pub_topic, "hello world - esp32 connected");
      // ... and resubscribe
      client.subscribe(sub_topic);
    }
    else
    {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void setup()
{
  // Set the Motor pins as outputs
  pinMode(motor1Pin1, OUTPUT);
  pinMode(motor1Pin2, OUTPUT);
  pinMode(motor2Pin1, OUTPUT);
  pinMode(motor2Pin2, OUTPUT);

  // Configure PWM channel functionalities
  ledcSetup(pwmChannel, freq, resolution);

  // Attach the PWM channel 0 to the enable pins which are the GPIOs to be controlled
  ledcAttachPin(enable1Pin, pwmChannel);
  ledcAttachPin(enable2Pin, pwmChannel);

  // Produce a PWM signal to both enable pins with a duty cycle 0
  ledcWrite(pwmChannel, dutyCycle);

  Serial.println(subscribedMsg);
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);
}

void loop()
{
  if (!client.connected())
  {
    reconnect();
  }
  client.loop();

  if (strcmp(decryptedtext_now, "forward")==0) {
    digitalWrite(motor1Pin1, LOW);
    digitalWrite(motor1Pin2, HIGH);
    digitalWrite(motor2Pin1, LOW);
    digitalWrite(motor2Pin2, HIGH);
  }
  else if (strcmp(decryptedtext_now, "left")==0) {
    digitalWrite(motor1Pin1, LOW);
    digitalWrite(motor1Pin2, HIGH);
    digitalWrite(motor2Pin1, LOW);
    digitalWrite(motor2Pin2, LOW);
  }
  else if (strcmp(decryptedtext_now, "stop")==0) {
    digitalWrite(motor1Pin1, LOW);
    digitalWrite(motor1Pin2, LOW);
    digitalWrite(motor2Pin1, LOW);
    digitalWrite(motor2Pin2, LOW);
  }
  else if (strcmp(decryptedtext_now, "right")==0) {
    digitalWrite(motor1Pin1, LOW);
    digitalWrite(motor1Pin2, LOW);
    digitalWrite(motor2Pin1, LOW);
    digitalWrite(motor2Pin2, HIGH);
  }
  else if (strcmp(decryptedtext_now, "reverse")==0) {
    digitalWrite(motor1Pin1, HIGH);
    digitalWrite(motor1Pin2, LOW);
    digitalWrite(motor2Pin1, HIGH);
    digitalWrite(motor2Pin2, LOW);
  }
  if (strcmp(decryptedtext_now, "0")==0) {
    ledcWrite(pwmChannel, 0);    
    digitalWrite(motor1Pin1, LOW);
    digitalWrite(motor1Pin2, LOW);
    digitalWrite(motor2Pin1, LOW);
    digitalWrite(motor2Pin2, LOW);
  }
  else if((int)decryptedtext_now > 0){
    dutyCycle = map((int)decryptedtext_now, 25, 100, 200, 255);
    ledcWrite(pwmChannel, dutyCycle);
  }
}
