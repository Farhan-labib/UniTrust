#!/bin/bash
# this runs the University Registrar B Agent example as a local instance of aca-py
# you need to run a local von-network (in the von-network directory run "./manage start <your local ip> --logs")
# ... and you need to install the local aca-py python libraries locally ("pip install -r ../requirements.txt -r ../requirements.indy.txt -r ../requirements.bbs.txt")

# Check if ngrok tunnel is available - better extraction for ngrok v3
NGROK_ENDPOINT=$(curl --silent localhost:4040/api/tunnels | jq -r '.tunnels[] | select(.proto=="https") | .public_url')
if [ -z "$NGROK_ENDPOINT" ] || [ "$NGROK_ENDPOINT" = "null" ]; then
  # Try alternative extraction for different ngrok versions
  NGROK_ENDPOINT=$(curl --silent localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
  if [ -z "$NGROK_ENDPOINT" ] || [ "$NGROK_ENDPOINT" = "null" ]; then
    echo "No ngrok tunnel found. Using localhost endpoint."
    ENDPOINT="http://127.0.0.1:8090"
  else
    echo "Using ngrok endpoint (method 2): $NGROK_ENDPOINT"
    ENDPOINT=$NGROK_ENDPOINT
  fi
else
  echo "Using ngrok endpoint (method 1): $NGROK_ENDPOINT"
  ENDPOINT=$NGROK_ENDPOINT
fi

# Ensure the endpoint does not end with a slash
ENDPOINT=$(echo $ENDPOINT | sed 's/\/$//')
echo "Final endpoint: $ENDPOINT"

# Pass the endpoint as an environment variable to the Python script
ENDPOINT=$ENDPOINT PYTHONPATH=.. python3 -m runners.uni_reg_b $@