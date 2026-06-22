#!/bin/bash

# ==========================================
# FAIL2BAN TEST SCRIPT
# ==========================================
# Define your target SSH server details below:
SERVER_IP="192.168.15.10" # Replace with your server's IP address.
SERVER_PORT="22"         # Replace with the SSH port if it's different.
ATTEMPTS=10              # Number of attempts (exceed your fail2ban maxretry))

echo "Initiating an access attempt to test Fail2ban on the server. $SERVER_IP..."

for i in $(seq 1 $ATTEMPTS); do
    echo "Attempt number $i..."
    # Try logging in with a non-existent username using a fake password and discard the error.
    sshpass -p "wrong_password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 fakeuser@$SERVER_IP -p $SERVER_PORT 2>/dev/null
    
    # Brief pauses between requests (don't let it go too quickly so that SSH closes automatically).
    sleep 1
done

echo "Script completed. Check the fail2ban status on your server!"
