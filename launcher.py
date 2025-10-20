import subprocess
import time
import os

# Start Flask backend
print("🚀 Starting Flask server...")
server = subprocess.Popen(["python", "server.py"])

# Wait few seconds for server to start
time.sleep(3)

# Start client (Python or EXE)
print("⚙️ Starting automation client...")
subprocess.Popen(["python", "cohodampati.py"])

# Keep launcher alive
print("✅ Both systems started successfully!")
server.wait()
