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

WiFiClient espClient;
PubSubClient client(espClient);

unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE (50)
char subscribedMsg[MSG_BUFFER_SIZE];
char msg[MSG_BUFFER_SIZE];
int value = 0;

#if !defined(CRYPTO_KEYBYTES)
#define CRYPTO_KEYBYTES 16
#endif
#if !defined(CRYPTO_NPUBBYTES)
#define CRYPTO_NPUBBYTES 16
#endif

#define TAGLEN 16

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
  Serial.begin(115200); // Initialize the Serial Monitor

  // Rest of the setup code
  setup_wifi();
  client.setServer(mqtt_server, 1883);
}

void loop()
{
  if (!client.connected())
  {
    reconnect();
  }
  client.loop();

  // Check if there is any input from the Serial Monitor
  if (Serial.available())
  {
    // Read the input message from Serial Monitor
    String message = Serial.readString();
    Serial.printf("Plaintext: %s", message.c_str());
    Serial.println("");
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
    client.publish(sub_topic, hexCiphertext);
  }
}
