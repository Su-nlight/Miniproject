#include <avr/eeprom.h>
#include <usbdrv.h>
#include <util/delay.h>

#define SECRET_KEY_LENGTH 16
#define CHALLENGE_KEY 0x55 // Basic XOR challenge key for encryption/decryption

uint8_t EEMEM eeprom_secret_key[SECRET_KEY_LENGTH];
uint8_t EEMEM eeprom_is_authorized = 0;

// Function to encrypt/decrypt data using XOR (simplistic, for demonstration)
void xorEncryptDecrypt(uint8_t *data, uint8_t length, uint8_t key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

// Handle USB control transfer
usbMsgLen_t usbFunctionSetup(uint8_t data[8]) {
    usbRequest_t *rq = (usbRequest_t *)data;
    
    // Challenge-response authorization mechanism
    if (rq->bRequest == 0x10) { // Request for authorization challenge
        uint8_t challenge = CHALLENGE_KEY;
        usbMsgPtr = &challenge; // Send the challenge key to the host
        return 1; // Return 1 byte (the challenge)
    }

    if (rq->bRequest == 0x11) { // Host response for authorization
        uint8_t response = rq->wValue.word;
        // XOR back to verify if it matches the challenge
        if (response == (CHALLENGE_KEY ^ 0xFF)) {  // Example expected response
            eeprom_write_byte(&eeprom_is_authorized, 1); // Authorized
        } else {
            eeprom_write_byte(&eeprom_is_authorized, 0); // Not authorized
        }
        return 0;
    }

    // Store secret key in EEPROM if authorized
    if (rq->bRequest == 0x20) { 
        uint8_t is_authorized = eeprom_read_byte(&eeprom_is_authorized);
        if (is_authorized) {
            uint8_t secret[SECRET_KEY_LENGTH];
            for (int i = 0; i < SECRET_KEY_LENGTH; i++) {
                secret[i] = rq->wIndex.bytes[i];
            }
            xorEncryptDecrypt(secret, SECRET_KEY_LENGTH, CHALLENGE_KEY); // Encrypt data
            for (int i = 0; i < SECRET_KEY_LENGTH; i++) {
                eeprom_write_byte(&eeprom_secret_key[i], secret[i]);
            }
        }
        return 0;
    }

    // Retrieve secret key from EEPROM if authorized
    if (rq->bRequest == 0x30) {
        uint8_t is_authorized = eeprom_read_byte(&eeprom_is_authorized);
        if (is_authorized) {
            uint8_t secret[SECRET_KEY_LENGTH];
            for (int i = 0; i < SECRET_KEY_LENGTH; i++) {
                secret[i] = eeprom_read_byte(&eeprom_secret_key[i]);
            }
            xorEncryptDecrypt(secret, SECRET_KEY_LENGTH, CHALLENGE_KEY); // Decrypt data
            usbMsgPtr = secret;  // Send decrypted data
            return SECRET_KEY_LENGTH;
        } else {
            return 0;  // Unauthorized access, no data sent
        }
    }

    return 0;
}

int main() {
    usbInit();
    usbDeviceDisconnect();
    _delay_ms(250);
    usbDeviceConnect();

    sei(); // Enable interrupts

    while (1) {
        usbPoll();
    }
}
