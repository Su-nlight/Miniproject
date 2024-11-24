from bleak import BleakClient

# BLE characteristics UUIDs
SERVICE_UUID = "12345678-1234-1234-1234-1234567890AB"
KEY_CHAR_UUID = "87654321-4321-4321-4321-0987654321AB"
PASSWORD_CHAR_UUID = "ABCDEF01-2345-6789-ABCD-EF0123456789"
REQUEST_COMMAND = "GET_ENCRYPTED_KEY"
# Replace with your ESP32 BLE device's address
DEVICE_ADDRESS = "40:91:51:9B:47:AE"

async def get_stored_encrypted_key(esp_password: str):
    try:
        async with BleakClient(DEVICE_ADDRESS) as client:
            await client.get_services()
            if not await client.is_connected():
                return {"Message": "Failed to connect to the device."}
            await client.write_gatt_char(PASSWORD_CHAR_UUID, esp_password.encode("utf-8"))
            await client.write_gatt_char(KEY_CHAR_UUID, REQUEST_COMMAND.encode("utf-8"))
            encrypted_key = await client.read_gatt_char(KEY_CHAR_UUID)
            encrypted_key = encrypted_key.decode("utf-8")
            if encrypted_key == "Access Denied: Authenticate First":
                return {"Message": "Access Denied"}

            if encrypted_key == "No key stored":
                return None

            return encrypted_key

    except OSError:
        return {"Message": "Bluetooth not configured."}

async def new_device_setup(new_esp_password:str, new_encryption_key:str):
    try:
        async with BleakClient(DEVICE_ADDRESS) as client:
            if not await client.is_connected():
                return {"Message": "Failed to connect to the device."}

    except OSError:
        return {"Message": "Bluetooth not configured."}

    await client.write_gatt_char(PASSWORD_CHAR_UUID, new_esp_password.encode("utf-8"))
    await client.write_gatt_char(KEY_CHAR_UUID, new_encryption_key.encode("utf-8"))
    response = await client.read_gatt_char(KEY_CHAR_UUID).decode()
    if response == "Encrypted key stored securely.":
        return {"message": "Device Setup Complete"}
    else:
        return {"message": "Device Setup Failed"}

async def update_encryption_key(esp_password:str, new_encryption_key: str):
    try:
        async with BleakClient(DEVICE_ADDRESS) as client:
            if not await client.is_connected():
                return {"Message": "Failed to connect to the device."}

    except OSError:
        return {"Message": "Bluetooth not configured."}

    await client.write_gatt_char(PASSWORD_CHAR_UUID, esp_password.encode("utf-8"))
    await client.write_gatt_char(KEY_CHAR_UUID, new_encryption_key.encode("utf-8"))
    response = await client.read_gatt_char(KEY_CHAR_UUID).decode()
    if response == "Encrypted key stored securely.":
        return {"message": "Encryption Key Updation Complete"}
    else:
        return {"message": "Encryption Key Updation Failed"}

