import asyncio
from bleak import BleakClient

# BLE characteristics UUIDs
SERVICE_UUID = "12345678-1234-1234-1234-1234567890AB"
KEY_CHAR_UUID = "87654321-4321-4321-4321-0987654321AB"
PASSWORD_CHAR_UUID = "ABCDEF01-2345-6789-ABCD-EF0123456789"
REQUEST_COMMAND = "GET_ENCRYPTED_KEY"

# Replace with your ESP32 BLE device's address
DEVICE_ADDRESS = "40:91:51:9B:47:AE"

# Menu Functions
async def set_password(client):
    password = input("Enter the password to set: ")
    await client.write_gatt_char(PASSWORD_CHAR_UUID, password.encode("utf-8"))
    print("Password set successfully!")

async def send_request_command(client):
    await client.write_gatt_char(KEY_CHAR_UUID, REQUEST_COMMAND.encode("utf-8"))
    encrypted_key = await client.read_gatt_char(KEY_CHAR_UUID)
    print(f"Encrypted key retrieved: {encrypted_key}")

async def write_encrypted_key(client):
    encrypted_key = input("Enter the encrypted key to store: ")
    await client.write_gatt_char(KEY_CHAR_UUID, encrypted_key.encode("utf-8"))
    print("Encrypted key written successfully!")

async def main():
    async with BleakClient(DEVICE_ADDRESS) as client:
        if not await client.is_connected():
            print("Failed to connect to the device.")
            return

        print(f"Connected to {DEVICE_ADDRESS}")

        while True:
            print("\n===== MENU =====")
            print("1. Set Password")
            print("2. Request Encrypted Key")
            print("3. Write Encrypted Key")
            print("4. Exit")

            choice = input("Select an option (1-4): ")

            if choice == "1":
                await set_password(client)
            elif choice == "2":
                await send_request_command(client)
            elif choice == "3":
                await write_encrypted_key(client)
            elif choice == "4":
                print("Exiting...")
                break
            else:
                print("Invalid choice, please try again.")

if __name__ == "__main__":
    asyncio.run(main())
