import random
import time
from datetime import datetime, timedelta
import sys


def to_unix_time(year):
    return int(time.mktime(datetime(year, 1, 1, 0, 0).timetuple()))

def generate_hourly_timestamps(start_year, end_year):
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 1, 1)
    timestamps = []
    while start_date < end_date:
        timestamps.append(int(time.mktime(start_date.timetuple())))
        start_date += timedelta(hours=1)
    return timestamps

def generate_minute_timestamps(start_year, end_year):
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 1, 1)
    timestamps = []
    while start_date < end_date:
        timestamps.append(int(time.mktime(start_date.timetuple())))
        start_date += timedelta(minutes=1)  # Changed from hours to minutes
    return timestamps

def encrypt(msg: bytes, cur_time: float) -> bytes:
    cur_time_bytes = str(cur_time).encode()
    random.seed(cur_time_bytes)

    key = [random.randrange(256) for _ in msg]
    c = [m ^ k for (m, k) in zip(msg + cur_time_bytes, key + [0x42] * len(cur_time_bytes))]

    return bytes(c)

def decrypt(encrypted_msg: bytes, cur_time: float) -> bytes:
    cur_time_bytes = str(cur_time).encode()
    random.seed(cur_time_bytes)

    key = [random.randrange(256) for _ in encrypted_msg[:-len(cur_time_bytes)]]
    decrypted_msg = [encrypted_msg[i] ^ key[i] for i in range(len(encrypted_msg) - len(cur_time_bytes))]

    return bytes(decrypted_msg)


if __name__ == "__main__":

    original_message = "Test message for encryption and decryption".encode('utf-8')

    test_timestamp = time.time()
    # Encrypt the message
    encrypted_message = encrypt(original_message, test_timestamp)

    print("=== Encryption Test ===")
    print(f"Original Message: {original_message.decode()}")
    print(f"Encrypted Message (bytes): {encrypted_message}")

    # Decrypt the message using the encryption timestamp
    decrypted_message = decrypt(encrypted_message, test_timestamp)
    decrypted_text = decrypted_message.decode('utf-8', errors='ignore')
    print("\n=== Decryption Test ===")
    print(f"Decrypted Message: {decrypted_text}")


    # Validate if the encryption and decryption were successful
    validation_status = "Success" if original_message == decrypted_message else "Failure"
    print(f"{validation_status}: The decrypted message {'matches' if validation_status == 'Success' else 'does not match'} the original.")

    print("\n=== Brute Force Decryption Attempt ===")
    timestamps = generate_minute_timestamps(1970, 2024)
    print(f"generated {len(timestamps)} timestamps")
    #timestamps = generate_hourly_timestamps(1970, 2024)

    # encoded_message should be the actual encrypted message in bytes
    encoded_message = b"\xf2\xf7=...\xf5\x00 \x97st{{qusvwsltssuspp"

    print("\n=== Brute Force Decryption Attempt ===")

    total_attempts = len(timestamps)
    print(f"Total decryption attempts: {total_attempts}")

    for i, timestamp in enumerate(timestamps):
        decrypted_message = decrypt(encoded_message, timestamp)
        try:
            if "flag" in str(decrypted_message.decode('utf-8')):
                print(f"Success! Timestamp: {timestamp} - Decrypted Message: {decrypted_message.decode('utf-8')}")
                break
        except UnicodeDecodeError:
            pass

        # Update progress bar
        percent_complete = (i + 1) / total_attempts * 100
        sys.stdout.write(f"\rProgress: [{int(percent_complete // 2) * '#'}{(50 - int(percent_complete // 2)) * ' '}] {percent_complete:.2f}% complete")
        sys.stdout.flush()
    else:
        print("\nBrute force decryption failed: 'flag' not found.")