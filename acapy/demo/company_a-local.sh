#!/bin/bash
# This runs Verifier Agent as a local instance of aca-py
# Company A is a verifier-only agent that can verify credentials from any issuer
# You need to run a local von-network (in the von-network directory run "./manage start <your local ip> --logs")
# ... and you need to install the local aca-py python libraries locally ("pip install -r ../requirements.txt -r ../requirements.indy.txt -r ../requirements.bbs.txt")

# Set company_a to use port 8080 instead of 8090
COMPANY_A_PORT=8080
echo "Setting up company_a agent on port $COMPANY_A_PORT..."

# Simple approach: Check if ngrok is running on port 8080, if not start it
# First, kill any existing ngrok process
pkill ngrok || true
echo "Starting ngrok on port $COMPANY_A_PORT..."
ngrok http $COMPANY_A_PORT > /dev/null 2>&1 &
sleep 3  # Wait for ngrok to start

# Get the tunnel URL - specifically for port 8080
NGROK_TUNNEL=$(curl --silent localhost:4040/api/tunnels | jq -r '.tunnels[] | select(.config.addr | endswith(":'"$COMPANY_A_PORT"'")) | .public_url')

# If specific port selection fails, try to get the first tunnel
if [ -z "$NGROK_TUNNEL" ] || [ "$NGROK_TUNNEL" = "null" ]; then
  NGROK_TUNNEL=$(curl --silent localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
fi

if [ -z "$NGROK_TUNNEL" ] || [ "$NGROK_TUNNEL" = "null" ]; then
  echo "Failed to start ngrok tunnel. Using localhost endpoint."
  ENDPOINT="http://127.0.0.1:$COMPANY_A_PORT"
  echo "For mobile connections, please start ngrok manually: ngrok http $COMPANY_A_PORT"
else
  echo "Created ngrok tunnel: $NGROK_TUNNEL"
  ENDPOINT=$NGROK_TUNNEL
fi

# Ensure the endpoint does not end with a slash
ENDPOINT=$(echo $ENDPOINT | sed 's/\/$//')
echo "Company A Verifier Agent endpoint: $ENDPOINT"

# Set agent port to 8080
AGENT_PORT=$COMPANY_A_PORT

# Pass the endpoint as an environment variable to the Python script
ENDPOINT=$ENDPOINT PYTHONPATH=.. python3 -m runners.company_a --port $AGENT_PORT $@