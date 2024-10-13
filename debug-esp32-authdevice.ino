#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <Preferences.h>
#include <mbedtls/aes.h>

#define DEVICE_NAME             "Secure_ESP32_Device"
#define SERVICE_UUID            "12345678-1234-1234-1234-1234567890AB"
#define KEY_CHAR_UUID           "87654321-4321-4321-4321-0987654321AB"
#define PASSWORD_CHAR_UUID      "ABCDEF01-2345-6789-ABCD-EF0123456789"
#define REQUEST_COMMAND         "GET_ENCRYPTED_KEY"

Preferences preferences;

BLECharacteristic* keyCharacteristic;
BLECharacteristic* passwordCharacteristic;

bool deviceConnected = false;
bool isAuthenticated = false;

const int buttonPin = 15;  // GPIO pin connected to the button
const int ledPin = 2;      // Built-in LED pin on ESP32 DevKit V1
bool buttonPressed = false;

void IRAM_ATTR handleButtonPress() {
  // Interrupt handler for button press
  buttonPressed = true;
}
void blinkLED(int times, int delayTime) {
  for (int i = 0; i < times; i++) {
    digitalWrite(ledPin, HIGH);  // Turn the LED on
    delay(delayTime);
    digitalWrite(ledPin, LOW);   // Turn the LED off
    delay(delayTime);
  }
}

const uint8_t encryptionKey[32] = {
    0xCB, 0x17, 0x2F, 0x8F, 0x76, 0x61, 0x03, 0x17,
    0xA7, 0x8D, 0xE4, 0x2B, 0x03, 0x1B, 0xE7, 0x0E,
    0x11, 0xC9, 0x1C, 0x20, 0xA5, 0x59, 0xA7, 0x6F,
    0xD6, 0xEB, 0xA1, 0x22, 0x67, 0x34, 0xDC, 0xDA,
};

// Helper function to convert String to std::string
std::string stringToStdString(const String& str) {
    return std::string(str.c_str());
}

// Helper function to convert std::string to String (Arduino type)
String stdStringToString(const std::string& str) {
    return String(str.c_str());
}

// Function to convert a binary buffer to a hex string
String toHexString(const uint8_t* data, size_t length) {
    String hexString = "";
    for (size_t i = 0; i < length; i++) {
        hexString += String(data[i], HEX);
    }
    return hexString;
}

// Function to convert a hex string back to binary data
std::vector<uint8_t> fromHexString(const String& hexString) {
    std::vector<uint8_t> binaryData;
    for (size_t i = 0; i < hexString.length(); i += 2) {
        uint8_t byte = (uint8_t)strtol(hexString.substring(i, i + 2).c_str(), nullptr, 16);
        binaryData.push_back(byte);
    }
    return binaryData;
}

// Encrypt UTF-8 data
String encryptData(const std::string& data) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, encryptionKey, 256);

    size_t dataLength = data.length();
    size_t paddedLength = ((dataLength + 15) / 16) * 16;
    uint8_t inputBuffer[paddedLength];
    memset(inputBuffer, 0, paddedLength);
    memcpy(inputBuffer, data.data(), dataLength);

    uint8_t outputBuffer[paddedLength];
    for (size_t i = 0; i < paddedLength; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, inputBuffer + i, outputBuffer + i);
    }

    mbedtls_aes_free(&aes);

    return toHexString(outputBuffer, paddedLength);
}

// Decrypt encrypted data
std::string decryptData(const String& encryptedData) {
    std::vector<uint8_t> binaryData = fromHexString(encryptedData);
    size_t dataLength = binaryData.size();
    uint8_t inputBuffer[dataLength];
    memcpy(inputBuffer, binaryData.data(), dataLength);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, encryptionKey, 256);

    uint8_t outputBuffer[dataLength];
    for (size_t i = 0; i < dataLength; i += 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, inputBuffer + i, outputBuffer + i);
    }

    mbedtls_aes_free(&aes);

    return std::string((char*)outputBuffer, dataLength);
}

// BLE connection callbacks
class MyServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
        deviceConnected = true;
        Serial.println("Client connected");
    }

    void onDisconnect(BLEServer* pServer) {
        deviceConnected = false;
        isAuthenticated = false;
        Serial.println("Client disconnected");
        // Restart advertising after disconnection
        pServer->startAdvertising();
    }
};

// Callbacks for key characteristic
class KeyCharacteristicCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pCharacteristic) {
        if (!deviceConnected) return;

        std::string value = pCharacteristic->getValue(); // No conversion needed

        if (!isAuthenticated) {
            Serial.println("Access denied: Client not authenticated.");
            pCharacteristic->setValue("Access Denied: Authenticate First");
            return;
        }

        if (value == REQUEST_COMMAND) {
            // Client requests the encrypted key
            String encryptedKey = preferences.getString("encrypted_key", "");
            if (encryptedKey == "") {
                Serial.println("No encrypted key stored.");
                pCharacteristic->setValue("No key stored");
            } else {
                pCharacteristic->setValue(stringToStdString(encryptedKey)); // Convert Arduino String to std::string
                Serial.println("Encrypted key sent to client.");
            }
        } else {
            // Store the encrypted key
            String encryptedKey = encryptData(value);  // Encrypt the UTF-8 key
            preferences.putString("encrypted_key", encryptedKey); // Store in Preferences
            Serial.println("UTF-8 encrypted key stored securely.");
        }
    }
};

// Callbacks for password characteristic
class PasswordCharacteristicCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pCharacteristic) {
        if (!deviceConnected) return;

        std::string value = pCharacteristic->getValue();  // Expecting UTF-8 password

        // Retrieve stored encrypted password
        String storedEncryptedPassword = preferences.getString("password", "");

        if (storedEncryptedPassword == "") {
            // No password stored; this is the initial setup
            String encryptedPassword = encryptData(value);  // Encrypt the UTF-8 password
            preferences.putString("password", encryptedPassword);
            Serial.println("UTF-8 password stored securely.");
            isAuthenticated = true;
        } else {
            // Compare the stored password with the provided one after decryption
            std::string decryptedPassword = decryptData(storedEncryptedPassword);
            if (value == decryptedPassword) {
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
    // Initialize GPIO pin for the button
    pinMode(buttonPin, INPUT_PULLUP);  // Using INPUT_PULLUP with a button connected to ground
    attachInterrupt(buttonPin, handleButtonPress, FALLING);  // Trigger on falling edge (button press)

    // Initialize built-in LED pin
    pinMode(ledPin, OUTPUT);
    digitalWrite(ledPin, LOW); 
    blinkLED(4,700); // To inform that device has powered on

    // Initialize preferences
    preferences.begin("storage", false);

    // Initialize BLE
    BLEDevice::init(DEVICE_NAME);

    // Set up BLE security
    BLESecurity* pSecurity = new BLESecurity();
    pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_BOND);
    pSecurity->setCapability(ESP_IO_CAP_NONE);
    pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

    BLEServer* pServer = BLEDevice::createServer();
    pServer->setCallbacks(new MyServerCallbacks());

    // Create BLE Service
    BLEService* pService = pServer->createService(SERVICE_UUID);

    // Create BLE Characteristics
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

    // Start the service
    pService->start();

    // Start advertising
    BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);  // Minimum advertising interval
    pAdvertising->setMaxPreferred(0x12);  // Maximum advertising interval
    BLEDevice::startAdvertising();
    Serial.println("Waiting for a client connection to notify...");
}

void loop() {
   // Check if the button was pressed
  if (buttonPressed) {
    Serial.println("Button pressed, clearing preferences...");
    
    preferences.clear();  // Clear all preferences
    Serial.println("Preferences cleared.");
    
    // Blink the LED twice
    blinkLED(2, 500);  // Blink 2 times with 500ms delay

    buttonPressed = false;  // Reset the flag
  }
  // No special tasks in the main loop; everything is handled by callbacks
}
