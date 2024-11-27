#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <Preferences.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/bignum.h>  // For Big Number support

const char* primeStr = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
                       "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
                       "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
                       "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
                       "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
                       "FFFFFFFF FFFFFFFF";
mbedtls_mpi generator;

// BLE service and characteristic UUIDs
#define DEVICE_NAME             "Secure_ESP32_Device"
#define SERVICE_UUID           "12345678-1234-1234-1234-1234567890ab"
#define PUB_KEY_CHAR_UUID      "abcdef01-1234-5678-1234-56789abcdef0"
#define CLIENT_PUB_KEY_CHAR_UUID "abcdef02-1234-5678-1234-56789abcdef1"
#define KEY_CHAR_UUID           "66ed9aa1-e85a-449c-befd-b0ec63c7dd60"
#define PASSWORD_CHAR_UUID      "5140c2d1-6c03-4388-88c0-cbbaa6aaafbd"
#define REQUEST_COMMAND         "GET_ENCRYPTED_KEY"

BLECharacteristic pubKeyCharacteristic(PUB_KEY_CHAR_UUID, BLECharacteristic::PROPERTY_READ);
BLECharacteristic clientPubKeyCharacteristic(CLIENT_PUB_KEY_CHAR_UUID, BLECharacteristic::PROPERTY_WRITE);

Preferences preferences;

BLECharacteristic* keyCharacteristic;
BLECharacteristic* passwordCharacteristic;
BLEService *pService;

bool deviceConnected = false;
bool isAuthenticated = false;

const int buttonPin = 15;
const int ledPin = 2;
volatile bool buttonPressed = false;

void IRAM_ATTR handleButtonPress() {
    static unsigned long last_interrupt_time = 0;
    unsigned long interrupt_time = millis();
    if (interrupt_time - last_interrupt_time > 200) { // 200 ms debounce time
        buttonPressed = true;
    }
    last_interrupt_time = interrupt_time;
}
void blinkLED(int times, int delayTime) {
  for (int i = 0; i < times; i++) {
    digitalWrite(ledPin, HIGH);
    delay(delayTime);
    digitalWrite(ledPin, LOW);
    delay(delayTime);
  }
}

// Function prototypes
void generatePrivateKey();
void computePublicKey();
void computeSharedSecret(const mbedtls_mpi* clientPubKey);
void deriveKeyFromSharedSecret();
String toHexString(const uint8_t* data, size_t length);
void fromHexString(const String& hexString, uint8_t* output, size_t* outputLength);
String encryptData(const String& data);
String decryptData(const String& encryptedData);

// Global variables for Diffie-Hellman
mbedtls_mpi privateKey, publicKey, sharedSecret, prime;

// Derived encryption key (from shared secret)
uint8_t encryptionKey[32];

// Generate private key
void generatePrivateKey() {
    mbedtls_mpi_init(&privateKey);
    mbedtls_mpi_gen_prime(&privateKey, 256, 1, NULL, NULL);
}

// Compute public key (g^privateKey % p)
void computePublicKey() {
    mbedtls_mpi_init(&publicKey);
    mbedtls_mpi_grow(&publicKey, 256);
    mbedtls_mpi_init(&generator);
    mbedtls_mpi_lset(&generator, 2);
    mbedtls_mpi_init(&prime);
    mbedtls_mpi_read_string(&prime, 16, primeStr);
    

    mbedtls_mpi_exp_mod(&publicKey, &generator, &privateKey, &prime, NULL);
}

// Compute shared secret (clientPubKey^privateKey % p)
void computeSharedSecret(const mbedtls_mpi* clientPubKey) {
    mbedtls_mpi_init(&sharedSecret);
    mbedtls_mpi_exp_mod(&sharedSecret, clientPubKey, &privateKey, &prime, NULL);
    deriveKeyFromSharedSecret();
}

// Convert BigInt shared secret to AES key using SHA-256
void deriveKeyFromSharedSecret() {
    uint8_t sharedSecretBytes[256 / 8];
    mbedtls_mpi_write_binary(&sharedSecret, sharedSecretBytes, sizeof(sharedSecretBytes));

    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts_ret(&sha256_ctx, 0);
    mbedtls_sha256_update_ret(&sha256_ctx, sharedSecretBytes, sizeof(sharedSecretBytes));
    mbedtls_sha256_finish_ret(&sha256_ctx, encryptionKey);
    mbedtls_sha256_free(&sha256_ctx);
}

String toHexString(const uint8_t* data, size_t length) {
    String hexString = "";
    for (size_t i = 0; i < length; i++) {
        if (data[i] < 0x10) hexString += "0";
        hexString += String(data[i], HEX);
    }
    return hexString;
}

void fromHexString(const String& hexString, uint8_t* output, size_t* outputLength) {
    size_t len = hexString.length();
    *outputLength = len / 2;
    for (size_t i = 0; i < len; i += 2) {
        output[i/2] = (uint8_t)strtol(hexString.substring(i, i + 2).c_str(), nullptr, 16);
    }
}

String encryptData(const String& data) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, encryptionKey, 256);

    size_t dataLength = data.length();
    size_t paddedLength = ((dataLength + 15) / 16) * 16;
    uint8_t inputBuffer[paddedLength];
    memset(inputBuffer, 0, paddedLength);
    memcpy(inputBuffer, data.c_str(), dataLength);

    // Add PKCS7 padding
    uint8_t paddingByte = paddedLength - dataLength;
    for (size_t i = dataLength; i < paddedLength; i++) {
        inputBuffer[i] = paddingByte;
    }

    uint8_t outputBuffer[paddedLength];
    for (size_t i = 0; i < paddedLength; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, inputBuffer + i, outputBuffer + i);
    }
    mbedtls_aes_free(&aes);

    return toHexString(outputBuffer, paddedLength);
}

// Decryption function (same as before, but now uses derived encryptionKey)
String decryptData(const String& encryptedData) {
    size_t dataLength = encryptedData.length() / 2;
    uint8_t inputBuffer[dataLength];
    size_t actualLength;
    fromHexString(encryptedData, inputBuffer, &actualLength);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, encryptionKey, 256);

    uint8_t outputBuffer[dataLength];
    for (size_t i = 0; i < dataLength; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, inputBuffer + i, outputBuffer + i);
    }
    mbedtls_aes_free(&aes);

    // Remove PKCS7 padding
    int paddingLength = outputBuffer[dataLength - 1];
    if (paddingLength > 0 && paddingLength <= 16) {
        for (int i = dataLength - paddingLength; i < dataLength; i++) {
            if (outputBuffer[i] != paddingLength) {
                // Invalid padding, return empty string or handle error
                return "";
            }
        }
        dataLength -= paddingLength;
    }

    return String((char*)outputBuffer, dataLength);
}

// Callback when client writes its public key
class ClientPubKeyCallback : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pCharacteristic) override {
        std::string clientPubKeyStr = pCharacteristic->getValue();
        
        mbedtls_mpi clientPubKey;
        mbedtls_mpi_init(&clientPubKey);
        mbedtls_mpi_read_string(&clientPubKey, 16, clientPubKeyStr.c_str());

        // Calculate shared secret
        computeSharedSecret(&clientPubKey);
        
        Serial.print("Shared Secret: ");
        Serial.println(toHexString(encryptionKey, sizeof(encryptionKey)));

        mbedtls_mpi_free(&clientPubKey);
    }
};

class MyServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
        deviceConnected = true;
        Serial.println("Client connected");
    }

    void onDisconnect(BLEServer* pServer) {
        deviceConnected = false;
        isAuthenticated = false;
        Serial.println("Client disconnected");
        pServer->startAdvertising();
    }
};

class KeyCharacteristicCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pCharacteristic) {
        if (!deviceConnected) return;

        if (!isAuthenticated) {
            Serial.println("Access denied: Client not authenticated.");
            pCharacteristic->setValue(encryptData("Access Denied: Authenticate First").c_str());
            return;
        }
        bool new_key_req = false;
        String value = pCharacteristic->getValue().c_str();
        value = decryptData(value);

        String encryptionKey2 = preferences.getString("encryption_key", "").c_str();
        
        if (new_key_req){
          preferences.putString("encryption_key", value);
          Serial.println("Encrypted key stored securely.");
          pCharacteristic->setValue(encryptData("Key Stored").c_str());
          return;
        }

        if (value == REQUEST_COMMAND) {
            if (encryptionKey2 == "") {
                Serial.println("No encrypted key stored.");
                pCharacteristic->setValue(encryptData("No key stored").c_str());
            } else {
                pCharacteristic->setValue(encryptData(encryptionKey2).c_str());
                Serial.println("Encrypted key sent to client.");
            }
        }
        else if(value == "NEW_ENCRYPTED_KEY" && encryptionKey2=="") {
            new_key_req = true;
        }
        else{
          Serial.println("Wrong method");
          pCharacteristic->setValue(encryptData("Wrong Method").c_str());
        }
    }
};

class PasswordCharacteristicCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pCharacteristic) {
        if (!deviceConnected) return;

        String value = pCharacteristic->getValue().c_str();
        value = decryptData(value);

        String storedPassword = preferences.getString("password", "");

        if (storedPassword == "") {
            preferences.putString("password", value);
            Serial.println("Password stored securely.");
            isAuthenticated = true;
        } else {
            if (value == storedPassword) {
                isAuthenticated = true;
                Serial.println("Client authenticated successfully.");
            } else {
                isAuthenticated = false;
                Serial.println("Authentication failed.");
            }
        }
    }
};

void setup() {
    Serial.begin(115200);
    pinMode(buttonPin, INPUT_PULLUP);
    attachInterrupt(buttonPin, handleButtonPress, FALLING);

    pinMode(ledPin, OUTPUT);
    digitalWrite(ledPin, LOW); 
    blinkLED(4, 700);

    preferences.begin("storage", false);

    BLEDevice::init(DEVICE_NAME);
    BLESecurity* pSecurity = new BLESecurity();
    pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_BOND);
    pSecurity->setCapability(ESP_IO_CAP_NONE);
    pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
    BLEServer *pServer = BLEDevice::createServer();
    
    pServer->setCallbacks(new MyServerCallbacks());
    pService = pServer->createService(SERVICE_UUID);

    // Generate private and public keys
    generatePrivateKey();
    computePublicKey();

    // Set up public key characteristic
    String publicKeyStr = toHexString(encryptionKey, sizeof(encryptionKey));
    pubKeyCharacteristic.setValue(publicKeyStr.c_str());
    pService->addCharacteristic(&pubKeyCharacteristic);

    clientPubKeyCharacteristic.setCallbacks(new ClientPubKeyCallback());
    pService->addCharacteristic(&clientPubKeyCharacteristic);

    keyCharacteristic = pService->createCharacteristic(
        KEY_CHAR_UUID,
        BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE
    );
    keyCharacteristic->setCallbacks(new KeyCharacteristicCallbacks());

    passwordCharacteristic = pService->createCharacteristic(
        PASSWORD_CHAR_UUID,
        BLECharacteristic::PROPERTY_WRITE
    );
    passwordCharacteristic->setCallbacks(new PasswordCharacteristicCallbacks());

    pService->start();
    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);
    pAdvertising->setMaxPreferred(0x12);
    pAdvertising->start();

    Serial.println("BLE Server started. Waiting for client...");
}

void loop() {
   if (buttonPressed) {
    Serial.println("Button pressed, clearing preferences...");
    preferences.clear();
    Serial.println("Preferences cleared.");
    blinkLED(2, 500);
    buttonPressed = false;
  }
}
