#include <DHT.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>

// ----------------
// PIN DEFINITION
// ----------------

#define BUTTON_PIN 27
#define BUTTON_PIN_EXT 13
#define RED_LED_PIN 32
#define WHITE_LED_PIN 33
#define RED_LED_PIN_EXT 12
#define YELLOW_LED_PIN_EXT 14
#define GREEN_LED_PIN_EXT 25
#define DHT11_PIN 26

// -----------------------------
// WIFI & MQTT server DEFINITION
// -----------------------------

#define SSID ""
#define WIFI_PWD ""
#define SRV ""
#define SRV_PORT 1883

// -----------
// MQTT TOPICS
// -----------

//#define TELEMETRY_ESP "telemetry/esp1"
#define COMMIT_ESP_1 "commit/esp1"
#define SALT_ESP_1 "salt/esp1"

#define TELEMETRY_ESP "telemetry/esp2"
#define COMMIT_ESP_2 "commit/esp2"
#define SALT_ESP_2 "salt/esp2"

// ----
// KEYS
// ----
const char *rsa_private_key = R"KEY(
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
)KEY";

const char* rsa_public_key = R"KEY(
-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----
)KEY";

const char* rsa_public_key_tele = R"KEY(
-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----
)KEY"; 
// ------------------
// COMMITEMENT SCHEME
// ------------------

enum State {
  IDLE,
  CHOOSING,
  WAITING,
  SALT,
  RESET,
  TIMEOUT
};

enum Choice {
  EVEN,
  ODD
};

#define TIMEOUT_THRESHOLD 60000
#define SHORT_PRESS_TIME 1000

// Button choice EVEN/ODD
int button_ext_last_state = LOW;  
int button_ext_current_state = LOW;
unsigned long button_ext_pressed_time  = 0;
unsigned long button_ext_released_time = 0;

// Commitement datas
State current_state = IDLE; // State of esp in the scheme
Choice current_choice = ODD; // Choice wanted by the user to be commited
uint8_t commit_salt[16]; // Salt used as key to get be used by other esp to verify commit
uint8_t other_esp_commit[36]; // Store other esp commitement
uint8_t other_esp_salt[16]; // Store other esp salt for verif 
unsigned long commit_start_time = 0; // Track for timeout
bool manual_start = false; // Detect if scheme started by this esp or the other => false = other esp started

// ------------
// GLOBAL SETUP
// ------------

// WIFI and MQTT Client Setup
WiFiClient wifiClient;
PubSubClient client(wifiClient);

// Link Sensor to PIN
DHT dht11(DHT11_PIN, DHT11);

// GLOBAL RNG VAR for crypto
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

//Limit Telemetry Spam
size_t telemetry_counter = 0;


// ------------------------------
// CYPHER and SIGNATURE functions
// ------------------------------
/**
 * @brief Launch the context for RNG VAR
 */
void init_rng() {
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
}

/**
 * @brief Encrypts a message using an RSA public key.
 *
 * @param public_key_pem  Null-terminated PEM string of the RSA public key.
 * @param message         Pointer to the message data to encrypt.
 * @param message_len     Length of the message in bytes.
 * @param output          Buffer where the encrypted message will be stored.
 * @param output_len      Pointer to a size_t variable that will contain the actual length of the encrypted data.
 * @param max_output_size Maximum number of bytes that can be written to the output buffer.
 *
 * @return true if encryption succeeded, false otherwise.
 */
bool rsa_encrypt(const char* public_key_pem, const unsigned char * message, size_t message_len, unsigned char* output, size_t* output_len, size_t max_output_size){
  if (max_output_size < 256) {
    Serial.printf("rsa_encrypt : Output buffer too small");
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  // Parse public key into pk context
  if (mbedtls_pk_parse_public_key(&pk, (const unsigned char*)public_key_pem, strlen(public_key_pem) + 1) != 0) {
    Serial.println("rsa_encrypt: Failed to parse RSA pub key");
    mbedtls_pk_free(&pk);
    return false;
  }

  // Check if the given key is RSA
  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    Serial.println("rsa_encrypt: Key is not RSA.");
    mbedtls_pk_free(&pk);
    return false;
  }

  // Encrypt message
  if (mbedtls_pk_encrypt(&pk, message, message_len, output, output_len, max_output_size, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
    Serial.println("rsa_encrypt: RSA encryption failed");
    Serial.println(mbedtls_pk_encrypt(&pk, message, message_len, output, output_len, max_output_size, mbedtls_ctr_drbg_random, &ctr_drbg));
    mbedtls_pk_free(&pk);
    return false;
  }

  mbedtls_pk_free(&pk);
  return true;
}

/**
 * @brief Decrypts an RSA-encrypted message using a private key.
 *
 * @param private_key_pem    Null-terminated PEM string of the RSA private key.
 * @param encrypted_msg      Pointer to the encrypted message.
 * @param encrypted_msg_len  Length of the encrypted message.
 * @param output             Buffer where the decrypted message will be stored.
 * @param output_len         Pointer to a size_t variable that will contain the actual number of bytes written.
 * @param max_output_size    Maximum size of the output buffer.
 *
 * @return true if decryption succeeded, false otherwise.
 */
bool rsa_decrypt(const char* private_key_pem, const unsigned char* encrypted_msg, size_t encrypted_msg_len, unsigned char* output, size_t* output_len, size_t max_output_size){
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  // Parse private key into pk context
  if (mbedtls_pk_parse_key(&pk, (const unsigned char*)private_key_pem, strlen(private_key_pem) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      Serial.println("rsa_decrypt: Failed to parse RSA priv key");
      mbedtls_pk_free(&pk);
      return false;
  }

  // Check if the given key is RSA
  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    Serial.println("rsa_decrypt: Key is not RSA.");
    mbedtls_pk_free(&pk);
    return false;
  }

  // Decrypt message
  if (mbedtls_pk_decrypt(&pk, encrypted_msg, encrypted_msg_len, output, output_len, max_output_size, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      Serial.println("rsa_decrypt: RSA decryption failed");
      mbedtls_pk_free(&pk);
      return false;
  }
  
  mbedtls_pk_free(&pk);
  return true;
}

/**
 * @brief Signs a message using RSA private key and SHA-256 hash.
 *
 * @param private_key_pem  Null-terminated PEM string of the RSA private key.
 * @param message          Pointer to the message to sign.
 * @param message_len      Length of the message in bytes.
 * @param signature        Buffer where the signature will be stored.
 * @param signature_len    Pointer to a size_t variable that will contain the actual number of bytes written for the signature.
 * @param max_output_size  Maximum buffer size for the signature.
 *
 * @return true if signing succeeded, false otherwise.
 */
bool rsa_sign(const char* private_key_pem, const unsigned char* message, size_t message_len, unsigned char* signature, size_t* signature_len, size_t max_output_size) {
  // Hash SHA-256
  uint8_t hash[32];
  if (mbedtls_sha256(message, message_len, hash, 0) != 0){
    Serial.println("rsa_sign: Failed to hash message in rsa_sign");
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  // Parse private key into pk context
  if (mbedtls_pk_parse_key(&pk, (const unsigned char*)private_key_pem, strlen(private_key_pem) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      Serial.println("rsa_sign: Failed to parse RSA priv key");
      mbedtls_pk_free(&pk);
      return false;
  }

  // Check if the given key is RSA
  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    Serial.println("rsa_sign: Key is not RSA.");
    mbedtls_pk_free(&pk);
    return false;
  }

  // Sign the hash message
  if(mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, max_output_size, signature_len, mbedtls_ctr_drbg_random, &ctr_drbg) != 0){
    Serial.println("rsa_sign: Failed to sign");
    mbedtls_pk_free(&pk);
    return false;
  }

  mbedtls_pk_free(&pk);
  return true;
}

/**
 * @brief Verifies an RSA signature using SHA-256.
 *
 * @param public_key_pem  Null-terminated PEM string of the RSA public key.
 * @param message         Pointer to the original message.
 * @param message_len     Length of the message in bytes.
 * @param signature       Pointer to the signature to verify.
 * @param signature_len   Length of the signature in bytes.
 *
 * @return true if verification succeeds, false otherwise.
 */
bool rsa_verify(const char* public_key_pem, const unsigned char* message, size_t message_len, const unsigned char* signature, size_t signature_len){
  // Hash SHA-256
  uint8_t hash[32];
  if (mbedtls_sha256(message, message_len, hash, 0) != 0){
    Serial.println("rsa_verify: Failed to hash message in rsa_sign");
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  // Parse public key into pk context
  if (mbedtls_pk_parse_public_key(&pk, (const unsigned char*)public_key_pem, strlen(public_key_pem) + 1) != 0) {
    Serial.println("rsa_verify: Failed to parse RSA pub key");
    mbedtls_pk_free(&pk);
    return false;
  }

  if (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, signature_len) != 0) {
      Serial.println("rsa_verify: RSA verification failed");
      mbedtls_pk_free(&pk);
      return false;
  }

  mbedtls_pk_free(&pk);
  return true;
}

/**
 * @brief Signs a message with the sender's private RSA key and encrypts it using hybrid AES-GCM + RSA.
 *
 * Output format:
 * [RSA-encrypted AES key][IV][AES-GCM ciphertext][GCM tag]

 * @param sender_private_key_pem PEM-encoded RSA private key of the sender for signing.
 * @param recipient_public_key_pem PEM-encoded RSA public key of the recipient for AES key encryption.
 * @param message Pointer to the message bytes to encrypt.
 * @param message_len Length of the message in bytes.
 * @param output Pointer to the buffer where the encrypted payload will be written.
 * @param output_len Pointer to a variable that will receive the total length of the output buffer.
 * @param max_output_size Maximum size of the output buffer to prevent overflow.
 *
 * @return true if encryption and signing succeed, false otherwise.
 */
bool sign_and_encrypt_hybrid(const char* sender_private_key_pem, const char* recipient_public_key_pem, const unsigned char* message, size_t message_len, unsigned char* output, size_t* output_len, size_t max_output_size) {
  // Generate message signature
  unsigned char signature[256];
  size_t signature_len = 0;
  if (!rsa_sign(sender_private_key_pem, message, message_len, signature, &signature_len, sizeof(signature))) {
    Serial.println("sign_and_encrypt_hybrid: RSA Signature ERROR");
    return false;
  }

  // Build envelope
  size_t envelope_len = 4 + message_len + 4 + signature_len;
  unsigned char envelope[envelope_len];
  size_t offset = 0;

  uint32_t msg_len32 = (uint32_t)message_len;
  memcpy(envelope + offset, &msg_len32, 4);
  offset += 4;
  memcpy(envelope + offset, message, message_len);
  offset += message_len;
  uint32_t sig_len32 = (uint32_t)signature_len;
  memcpy(envelope + offset, &sig_len32, 4);
  offset += 4;
  memcpy(envelope + offset, signature, signature_len);
  offset += signature_len;

  // Generate AES key and IV
  unsigned char aes_key[16]; // AES-128
  unsigned char iv[12];

  mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, sizeof(aes_key));
  mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv));

  // Encrypt envelope with AES-GCM 
  unsigned char aes_encrypted[envelope_len];
  unsigned char tag[16];

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 128);
  if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, envelope_len, iv, sizeof(iv), NULL, 0, envelope, aes_encrypted, sizeof(tag), tag) != 0) {
    Serial.println("sign_and_encrypt_hybrid: AES-GCM encryption failed");
    mbedtls_gcm_free(&gcm);
    return false;
  }
  mbedtls_gcm_free(&gcm);

  // Encrypt AES key with RSA
  size_t encrypted_key_len = 256; // 2048-bit RSA
  unsigned char encrypted_key[256];
  if (!rsa_encrypt(recipient_public_key_pem, aes_key, sizeof(aes_key), encrypted_key, &encrypted_key_len, sizeof(encrypted_key))) {
    Serial.println("sign_and_encrypt_hybrid: RSA encryption of AES key failed");
    return false;
  }

  // [RSA_key][IV][AES_encrypted][tag]
  size_t total_len = encrypted_key_len + sizeof(iv) + envelope_len + sizeof(tag);
  if (total_len > max_output_size) {
      Serial.println("sign_and_encrypt_hybrid: Output buffer too small for hybrid GCM encryption");
      return false;
  }

  offset = 0;
  memcpy(output + offset, encrypted_key, encrypted_key_len);
  offset += encrypted_key_len;
  memcpy(output + offset, iv, sizeof(iv));
  offset += sizeof(iv);
  memcpy(output + offset, aes_encrypted, envelope_len);
  offset += envelope_len;
  memcpy(output + offset, tag, sizeof(tag));
  offset += sizeof(tag);

  *output_len = total_len;

  return true;
}

/**
 * @brief Decrypts a hybrid AES-GCM + RSA-encrypted message and verifies the sender's signature.
 *
 * @param recipient_private_key_pem PEM-encoded RSA private key of the recipient.
 * @param sender_public_key_pem PEM-encoded RSA public key of the sender.
 * @param input Pointer to the encrypted payload produced by sign_and_encrypt_hybrid().
 * @param input_len Length of the encrypted payload in bytes.
 * @param output Pointer to buffer where the decrypted message will be written.
 * @param output_len Pointer to a variable that will receive the length of the decrypted message.
 * @param max_output_size Maximum size of the output buffer to prevent overflow.
 *
 * @return true if decryption and signature verification succeed, false otherwise.
 */
bool decrypt_and_verify_hybrid(const char* recipient_private_key_pem, const char* sender_public_key_pem, const unsigned char* input, size_t input_len, unsigned char* output, size_t* output_len, size_t max_output_size) {
  size_t offset = 0;
  if (input_len < 256 + 12 + 16) {
      Serial.println("decrypt_and_verify_hybrid: Input too small");
      return false;
  }

  // Get RSA encrypted AES key
  unsigned char encrypted_key[256];
  memcpy(encrypted_key, input + offset, 256);
  offset += 256;

  // Get IV
  unsigned char iv[12];
  memcpy(iv, input + offset, 12);
  offset += 12;

  // Get Ciphertext + tag
  if (input_len < offset + 16) {
      Serial.println("decrypt_and_verify_hybrid: Invalid input length");
      return false;
  }
  size_t ciphertext_len = input_len - offset - 16;
  unsigned char* ciphertext = (unsigned char*)(input + offset);
  offset += ciphertext_len;

  unsigned char* tag = (unsigned char*)(input + offset);

  // Get plaintext AES key
  unsigned char aes_key[16];
  size_t aes_key_len = 0;
  if (!rsa_decrypt(recipient_private_key_pem, encrypted_key, sizeof(encrypted_key), aes_key, &aes_key_len, sizeof(aes_key))) {
      Serial.println("decrypt_and_verify_hybrid: RSA decryption of AES key failed");
      return false;
  }

  if (aes_key_len != sizeof(aes_key)) {
      Serial.println("decrypt_and_verify_hybrid: Unexpected AES key length");
      return false;
  }

  // Get plaintext envelope
  unsigned char envelope[ciphertext_len];

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 128) != 0) {
      Serial.println("decrypt_and_verify_hybrid: AES-GCM setkey failed");
      mbedtls_gcm_free(&gcm);
      return false;
  }

  if (mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, sizeof(iv), NULL, 0, tag, 16, ciphertext, envelope) != 0) {
      Serial.println("decrypt_and_verify_hybrid: AES-GCM authentication failed");
      mbedtls_gcm_free(&gcm);
      return false;
  }

  mbedtls_gcm_free(&gcm);

  // Parse envelope
  size_t env_offset = 0;
  if (env_offset + 4 > ciphertext_len) return false;
  uint32_t msg_len = *(uint32_t*)(envelope + env_offset);
  env_offset += 4;

  if (env_offset + msg_len + 4 > ciphertext_len) return false;
  const unsigned char* msg_ptr = envelope + env_offset;
  env_offset += msg_len;

  uint32_t sig_len = *(uint32_t*)(envelope + env_offset);
  env_offset += 4;

  if (sig_len > 256 || env_offset + sig_len > ciphertext_len) {
      Serial.println("decrypt_and_verify_hybrid: Invalid signature length");
      return false;
  }
  const unsigned char* sig_ptr = envelope + env_offset;

  // Check signature
  if (!rsa_verify(sender_public_key_pem, msg_ptr, msg_len, sig_ptr, sig_len)) {
      Serial.println("decrypt_and_verify_hybrid: RSA signature verification failed");
      return false;
  }

  // Output results
  if (msg_len > max_output_size) {
      Serial.println("decrypt_and_verify_hybrid: Plaintext buffer too small");
      return false;
  }

  memcpy(output, msg_ptr, msg_len);
  *output_len = msg_len;

  return true;
}

// ------------------------
// SERVERS HANDLE FUNCTIONS
// ------------------------

/**
 * @brief Wifi setup and connection
 */
void wifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, WIFI_PWD);
  Serial.print("INFO: Connecting to WiFi ..");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print('.');
    delay(1000);
  }
  Serial.println("INFO: Wifi connected");
  Serial.println(WiFi.localIP());
}

/**
 * @brief MQTT client conf + MQTT broker connection
 */
void mqtt_connection() {
  while (!client.connected()) {
    Serial.print("Connecting to MQTT Broker...");

    if (client.connect("ESP32Client_B")) {
      client.setBufferSize(2048);
      client.subscribe(COMMIT_ESP_1);
      client.subscribe(SALT_ESP_1);
      Serial.println("Connected!");
    } else {
      Serial.print("Failed, rc=");
      Serial.print(client.state());
      Serial.println(" retrying in 5 seconds");
      delay(5000);
    }
  }
}

// -------------------
// TELEMETRY FUNCTIONS
// -------------------

/**
 * @brief Debug fct: Print in Serial the telemetry
 *
 * @param humi  Humidity telemetry
 * @param tempC Temperature in Celcius telemetry
 */
void print_telemetry_results(float humi, float tempC){
  Serial.print("INFO: Humidity = ");
  Serial.print(humi);
  Serial.print(" %, Temperature = ");
  Serial.print(tempC);
  Serial.println(" °C");
}

/**
 * @brief Encrypts, Sign and Send Telemetry to MQTT Broker
 *
 * @param humi  Humidity telemetry
 * @param tempC Temperature in Celcius telemetry
 */
void send_telemetry(float humi, float tempC){
  char telemetry[34];
  snprintf(telemetry, sizeof(telemetry), "{\"humi\": %.2f, \"temp\": %.2f}", humi, tempC);

  unsigned char encrypted_msg[600];
  size_t encrypted_len = 0;

  if (!sign_and_encrypt_hybrid(rsa_private_key, rsa_public_key_tele, (unsigned char*)telemetry, strlen(telemetry), encrypted_msg, &encrypted_len, sizeof(encrypted_msg))) {
      Serial.println("send_telemetry: Failed to sign and encrypt telemetry");

  } else {
    char base64_msg[800];
    size_t base64_len = 0;
    
    if(mbedtls_base64_encode((unsigned char*)base64_msg, sizeof(base64_msg), &base64_len, encrypted_msg, encrypted_len) != 0){
      Serial.println("send_telemetry: Base64 encoding failed");

    } else {
      client.publish(TELEMETRY_ESP,(const uint8_t*)base64_msg, base64_len, true);
    }
  }
}

/**
 * @brief Legacy fct: Used to test telemetry verif before python client existed
 */
bool receive_telemetry(const char* base64_msg, size_t base64_len, const char* recipient_private_key, const char* sender_public_key, char* output_buffer, size_t max_output_size) {
  unsigned char encrypted_msg[600];
  size_t encrypted_len = 0;
  
  if (mbedtls_base64_decode(encrypted_msg, sizeof(encrypted_msg), &encrypted_len, (const unsigned char*)base64_msg, base64_len) != 0) {
    Serial.println("Base64 decoding failed");
    return false;
  }

  size_t plaintext_len = 0;
  if (!decrypt_and_verify_hybrid(recipient_private_key, sender_public_key, encrypted_msg, encrypted_len, (unsigned char*)output_buffer, &plaintext_len, max_output_size - 1)) {
    Serial.println("Decryption or signature verification failed");
    return false;
  }
  output_buffer[plaintext_len] = '\0';
  return true;
}

// ----------------------
// COMMITEMENTS FUNCTIONS
// ----------------------

/**
 * @brief Core of commitement scheme and handle its flow
 */
void handle_commitement(){
  if (digitalRead(BUTTON_PIN_EXT) == HIGH && current_state == IDLE){
    current_state = CHOOSING;
    manual_start = true;
  }

  switch (current_state) {
    case IDLE:
      digitalWrite(RED_LED_PIN_EXT, LOW);
      digitalWrite(YELLOW_LED_PIN_EXT, LOW);
      digitalWrite(GREEN_LED_PIN_EXT, LOW);
      break;
    
    case CHOOSING:
      digitalWrite(RED_LED_PIN_EXT, HIGH);
      //Select EVEN/ODD
      button_ext_current_state = digitalRead(BUTTON_PIN_EXT);

      // Button is pressed
      if (button_ext_last_state == LOW && button_ext_current_state == HIGH) {
        button_ext_pressed_time = millis();
      } else if (button_ext_last_state == HIGH && button_ext_current_state == LOW) { //button is released
        button_ext_released_time = millis();
        if ((button_ext_released_time - button_ext_pressed_time) < SHORT_PRESS_TIME ) { //Shot press = changing choice
          if (current_choice == EVEN) {
            current_choice = ODD;
            digitalWrite(YELLOW_LED_PIN_EXT, LOW);
          } else {
            current_choice = EVEN;
            digitalWrite(YELLOW_LED_PIN_EXT, HIGH);
          }
        } else { // Long Press = send commitement
          if (send_commit_choice()){
            Serial.println("Commit Send");
            digitalWrite(RED_LED_PIN_EXT, LOW);
            delay(200);
            digitalWrite(RED_LED_PIN_EXT, HIGH);

            if (manual_start) {
              current_state = WAITING;
            } else {
              current_state = SALT;
            }
          } else {
            Serial.println("ERROR Commit not Send");
          }
        }
      }

      button_ext_last_state = button_ext_current_state;
      break;

    case SALT:
      if (send_salt()) {
        Serial.println("Salt send");
        current_state = SALT;
      } else {
        Serial.println("ERROR Salt not Send");
      }
      break;
    case RESET:
    case TIMEOUT:
      reset_commitment_data();
      digitalWrite(RED_LED_PIN_EXT, LOW);
      digitalWrite(YELLOW_LED_PIN_EXT, LOW);
      digitalWrite(GREEN_LED_PIN_EXT, LOW);
      break;
  }
}

void reset_commitment_data() {
  memset(commit_salt, 0, sizeof(commit_salt));
  memset(other_esp_salt, 0, sizeof(other_esp_salt));
  memset(other_esp_commit, 0, sizeof(other_esp_commit));
  manual_start = false;
  commit_start_time = 0;
  current_state = IDLE;
  current_choice = ODD;
  
}

/**
 * @brief Handle the creation of the commitement based on user choice and send it to MQTT broker
 * Need to be in CHOOSING state to work
 * Flow: Random SALT => hash (choice|salt) => Sign + Encrypt => base64 encode => Send
 *
 * @return true if commitement was build and send is succesfull, false otherwise.
 */
bool send_commit_choice() {
  if (current_state != CHOOSING) return false;

  // Generate random salt
  mbedtls_ctr_drbg_random(&ctr_drbg, commit_salt, sizeof(commit_salt));

  // hash (choice || salt)
  uint8_t commit_hash[32];
  uint8_t buffer[1 + sizeof(commit_salt)];
  buffer[0] = (uint8_t)current_choice;
  memcpy(buffer + 1, commit_salt, sizeof(commit_salt));
  if (mbedtls_sha256(buffer, sizeof(buffer), commit_hash, 0) != 0){
    Serial.println("send_commit_choice: Failed to hash to create commitement");
    return false;
  }

  unsigned char encrypted_msg[600];
  size_t encrypted_len = 0;

  if (!sign_and_encrypt_hybrid(rsa_private_key, rsa_public_key, commit_hash, sizeof(commit_hash), encrypted_msg, &encrypted_len, sizeof(encrypted_msg))) {
    Serial.println("send_commit_choice: Failed to sign and encrypt commitment");
    return false;
  }

  char base64_msg[800];
  size_t base64_len = 0;

  if (mbedtls_base64_encode((unsigned char*)base64_msg, sizeof(base64_msg), &base64_len, encrypted_msg, encrypted_len) != 0) {
    Serial.println("send_commit_choice: Base64 encoding failed in commitment");
    return false;
  }

  client.publish(COMMIT_ESP_2, (const uint8_t*)base64_msg, base64_len, true);
  commit_start_time = millis();

  return true;
}

/**
 * @brief Handle the decryption, verification and storage of other esp commitement 
 * Is used by callback when commit is detected
 * Flow: Reverse of send_commit_choice
 *
 * @return true if commitement is valid and storage succesfull, false otherwise.
 */
bool receive_commit_choice(const char* base64_msg,  size_t base64_len, const char* recipient_private_key,  const char* sender_public_key) {
  unsigned char encrypted_msg[600];
  size_t encrypted_len = 0;

  if (mbedtls_base64_decode(encrypted_msg, sizeof(encrypted_msg), &encrypted_len, (const unsigned char*)base64_msg, base64_len) != 0) {
      Serial.println("receive_commit_choice: Base64 decoding failed in receive_commit_choice");
      return false;
  }

  size_t hash_len = 0;

  if (!decrypt_and_verify_hybrid(recipient_private_key, sender_public_key, encrypted_msg, encrypted_len, other_esp_commit, &hash_len, sizeof(other_esp_commit))) {
    Serial.println("receive_commit_choice: Decryption or signature verification failed");
    return false;
  }

  if (hash_len != 32) {
      Serial.printf("receive_commit_choice: Commit payload unexpected length: %u\n", hash_len);
      return false;
  }

  Serial.println("receive_commit_choice: Commitment received and verified.");
  return true;
}

/**
 * @brief Send choice + salt to MQTT Broker to enable other esp to verify
 * Need to be in SALT state to work
 *
 * @return true if send is succesfull, false otherwise.
 */
bool send_salt(){
  if (current_state != SALT) return false;

  // [choice | salt]
  uint8_t reveal_data[1 + sizeof(commit_salt)];
  reveal_data[0] = (uint8_t)current_choice;
  memcpy(reveal_data + 1, commit_salt, sizeof(commit_salt));

  unsigned char encrypted_msg[600];
  size_t encrypted_len = 0;

  if (!sign_and_encrypt_hybrid(rsa_private_key, rsa_public_key, reveal_data, sizeof(reveal_data), encrypted_msg, &encrypted_len, sizeof(encrypted_msg))) {
    Serial.println("Failed to sign and encrypt salt");
    return false;
  }

  char base64_msg[800];
  size_t base64_len = 0;

  if (mbedtls_base64_encode((unsigned char*)base64_msg, sizeof(base64_msg), &base64_len, encrypted_msg, encrypted_len) != 0) {
    Serial.println("Base64 encoding failed in send salt");
    return false;
  }

  client.publish(SALT_ESP_2, (const uint8_t*)base64_msg, base64_len, true);

  return true;
}

bool receive_salt_and_check_win(const char* base64_msg,  size_t base64_len, const char* recipient_private_key,  const char* sender_public_key){
  unsigned char encrypted_msg[600];
  size_t encrypted_len = 0;

  if (mbedtls_base64_decode(encrypted_msg, sizeof(encrypted_msg), &encrypted_len, (const unsigned char*)base64_msg, base64_len) != 0) {
      Serial.println("Base64 decoding failed in receive_commit_choice");
      return false;
  }

  uint8_t reveal_data[1 + 16];
  size_t reveal_len = 0;

  if (!decrypt_and_verify_hybrid(recipient_private_key, sender_public_key, encrypted_msg, encrypted_len, reveal_data, &reveal_len, sizeof(reveal_data))) {
    Serial.println("Decryption or signature verification failed");
    return false;
  }

  if (reveal_len != sizeof(reveal_data)) {
      Serial.printf("Salt unexpected length: %u\n", reveal_len);
      return false;
  }

  // Extract choice and salt
  uint8_t choice_raw = reveal_data[0];
  Choice received_choice = (choice_raw == 0 ? EVEN : ODD);

  uint8_t received_salt[16];
  memcpy(received_salt, reveal_data + 1, 16);
  Serial.println("Salt received and verified.");
  Serial.println("Check Win");
  bool win = verify_other_esp_commit(received_choice, received_salt);

  digitalWrite(RED_LED_PIN_EXT, LOW);
  digitalWrite(YELLOW_LED_PIN_EXT, LOW);
  digitalWrite(GREEN_LED_PIN_EXT, LOW);
  
  if (win){
    for (int i = 0; i < 5; i++){
      digitalWrite(GREEN_LED_PIN_EXT, HIGH);
      delay(300);
      digitalWrite(GREEN_LED_PIN_EXT, LOW);
      delay(200);
    }
  } else {
    for (int i = 0; i < 5; i++){
      digitalWrite(RED_LED_PIN_EXT, HIGH);
      delay(300);
      digitalWrite(RED_LED_PIN_EXT, LOW);
      delay(200);
    }
  }
  current_state = RESET;
  return true;
}

bool verify_other_esp_commit(Choice received_choice, const uint8_t received_salt[16]) {
  uint8_t buffer[1 + 16];
  buffer[0] = (uint8_t)received_choice;
  memcpy(buffer + 1, received_salt, 16);

  uint8_t computed_hash[32];

  if (mbedtls_sha256(buffer, sizeof(buffer), computed_hash, 0) != 0) {
      Serial.println("verify_other_esp_commit: SHA256 failed when verifying other ESP commitment");
      return false;
  }

  uint8_t stored_commit[32];
  memcpy(stored_commit, other_esp_commit, 32);

  if (!(memcmp(computed_hash, stored_commit, 32) == 0)) {
      Serial.println("verify_other_esp_commit: Commitment verification FAILED: hash mismatch");
      return false;
  }

  return (received_choice == current_choice);
}
/**
 * @brief Callback function used to handle incomming MQTT messages
 *
 */
void callback(char* topic, byte* payload, unsigned int length) {
  if (strcmp(topic, COMMIT_ESP_1) == 0) {
    if (current_state == IDLE || current_state == WAITING) {
      Serial.println("Commit received");
      // Convert payload to string
      String base64_msg = "";
      for (unsigned int i = 0; i < length; i++) {
          base64_msg += (char)payload[i];
      }

      if (!receive_commit_choice(base64_msg.c_str(), base64_msg.length(), rsa_private_key, rsa_public_key)) {
          Serial.println("Error Invalid commitement ");
      }

      if (current_state == WAITING) {
        current_state = SALT;
      }

      if (current_state == IDLE) {
        current_state = CHOOSING;
        manual_start = false;
        commit_start_time = millis();
      }
    }
  }
  if (strcmp(topic, SALT_ESP_1) == 0) {
    if (current_state != SALT) return;
    Serial.println("Salt received");
    // Convert payload to string
    String base64_msg = "";
    for (unsigned int i = 0; i < length; i++) {
        base64_msg += (char)payload[i];
    }
    if (!receive_salt_and_check_win(base64_msg.c_str(), base64_msg.length(), rsa_private_key, rsa_public_key)) {
          Serial.println("Error Invalid Salt ");
      }
  }
}

bool checkTimeout() {
  if ((current_state == WAITING || current_state == SALT || ( !manual_start && current_state == CHOOSING)) && millis() - commit_start_time > TIMEOUT_THRESHOLD) {
    current_state = TIMEOUT;
    Serial.println("Timeout");
    return true;
  }
  return false;
}

// ----------------------
// BASE FEATURE FUNCTIONS
// ----------------------

void led_button_press() {
  if (digitalRead(BUTTON_PIN) == HIGH){
    Serial.println("INFO: Button Pressed");
    digitalWrite(WHITE_LED_PIN, HIGH);
    digitalWrite(RED_LED_PIN, LOW);
    
  } else {
    digitalWrite(WHITE_LED_PIN, LOW);
    digitalWrite(RED_LED_PIN, HIGH);
  }
}

void setup() {
  Serial.begin(115200); //baud
  // Pin Setup
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(BUTTON_PIN_EXT, INPUT_PULLUP);
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(WHITE_LED_PIN, OUTPUT);
  pinMode(RED_LED_PIN_EXT, OUTPUT);
  pinMode(YELLOW_LED_PIN_EXT, OUTPUT);
  pinMode(GREEN_LED_PIN_EXT, OUTPUT);

  // Default Led Values
  digitalWrite(RED_LED_PIN, HIGH);
  digitalWrite(WHITE_LED_PIN, LOW);
  digitalWrite(RED_LED_PIN_EXT, LOW);
  digitalWrite(YELLOW_LED_PIN_EXT, LOW);
  digitalWrite(GREEN_LED_PIN_EXT, LOW);
  dht11.begin();

  // SRV Link
  wifi();
  client.setServer(SRV, SRV_PORT);
  client.setCallback(callback);
  mqtt_connection();

  // Crypto setup
  init_rng();

  // Telemetry counter
  telemetry_counter = 0;

  Serial.println("INIT OK");

}

void loop() {
  led_button_press();

  //reestablish connection to wifi if lost
  if (WiFi.status() != WL_CONNECTED){
    delay(1000);
    wifi();
  }

  // reestablish connection to thingboard if lost
  if (!client.connected()) {
    delay(1000);
    mqtt_connection();
  }
  client.loop();

  // Humidity and Temperature
  float humi  = dht11.readHumidity();
  float tempC = dht11.readTemperature();

  // Check if readings are valid
  if (isnan(humi) || isnan(tempC)) {
    Serial.println("ERROR: Failed to read from DHT11 sensor!");

  } else {
    //print_telemetry_results(humi, tempC);
    if (telemetry_counter >= 20) {
      send_telemetry(humi, tempC);
      telemetry_counter = 0;
    }
  }
  handle_commitement();
  checkTimeout();
  telemetry_counter += 1;
  delay(200); //delay
}
