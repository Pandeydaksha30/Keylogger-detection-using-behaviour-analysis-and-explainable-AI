import time
import os

# --- Configuration ---
FILENAME = "temp_keylogger_log.txt"
# The detector's ABNORMAL_WRITE_THRESHOLD is 1MB (1,000,000 bytes)
# We will write 3MB to guarantee a detection.
BYTES_TO_WRITE = 3_000_000
# ---------------------

print("Demo script starting...")
print(f"Will write {BYTES_TO_WRITE / (1024*1024):.2f}MB to '{FILENAME}' to trigger detector.")

try:
    with open(FILENAME, "w") as f:
        # Create a single large string and write it
        # This is fast and will look like a 'dump' of data
        data = 'a' * BYTES_TO_WRITE
        f.write(data)
    
    print(f"Successfully wrote {os.path.getsize(FILENAME)} bytes to {FILENAME}.")
    print("...Now wait for the detector to run its next check (within 5 seconds)...")

except Exception as e:
    print(f"Error writing file: {e}")

# Clean up the file after a few seconds
time.sleep(10)
if os.path.exists(FILENAME):
    os.remove(FILENAME)
    print(f"Cleaned up {FILENAME}.")

print("Demo script finished.")
