import usb.core
import usb.util

# Find the ATtiny85 USB device (use correct VID/PID for your device)
dev = usb.core.find(idVendor=0x16c0, idProduct=0x05df)

if dev is None:
    raise ValueError("Device not found")

# Set the configuration
dev.set_configuration()

# Step 1: Authorize the device
AUTHORIZATION_CODE = 0xA5  # Authorization code used in ATtiny85 firmware
try:
    dev.ctrl_transfer(0x40, 0x10, AUTHORIZATION_CODE, 0, None)
    print("Device authorized successfully.")
except:
    raise RuntimeError("Failed to authorize device.")

# Step 2: Send secret data to be stored (e.g., a 16-byte key)
secret_key = [ord(c) for c in "mysecretpassword"]  # Convert string to byte array
assert len(secret_key) == 16  # Ensure it fits within EEPROM size

try:
    dev.ctrl_transfer(0x40, 0x20, 0, 0, secret_key)  # Send key to EEPROM
    print("Secret key sent successfully.")
except:
    raise RuntimeError("Failed to send secret key.")

# Step 3: Retrieve stored data
try:
    response = dev.ctrl_transfer(0xC0, 0x30, 0, 0, 16)  # Request secret key from EEPROM
    retrieved_key = ''.join([chr(x) for x in response])
    print(f"Retrieved secret key: {retrieved_key}")
except:
    raise RuntimeError("Failed to retrieve secret key.")
