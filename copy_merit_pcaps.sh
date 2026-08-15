#!/bin/bash

# Configuration
REMOTE_HOST="zeus-acarbajal"
LOCAL_BASE_DIR="/home/axc/storage/sda1recrypt/data"

# Parameters matching your run_yearly_analysis.sh execution
YEARS="2021 2025"
TARGET_DAYS="15"
HOURS="00 06 12 18"
MONTHS="01 02 03 04 05 06 07 08 09 10 11 12"

echo "[*] Starting automated copy of Merit PCAP files..."
echo "[*] Remote Host: $REMOTE_HOST"
echo "[*] Local Target Directory: $LOCAL_BASE_DIR"
echo "---------------------------------------------------"

# Ensure local base directory exists
mkdir -p "$LOCAL_BASE_DIR"

for YEAR in $YEARS; do
  for MONTH in $MONTHS; do
    for d in $TARGET_DAYS; do
      # Pad day to 2 digits (e.g., 15)
      DAY=$(printf "%02d" $((10#$d)))

      # Create organized directory structure locally matching the remote VM layout
      LOCAL_DEST_DIR="$LOCAL_BASE_DIR/$YEAR/$MONTH/$DAY"
      mkdir -p "$LOCAL_DEST_DIR"

      for h in $HOURS; do
        # Pad hour to 2 digits (e.g., 00, 06, 12, 18)
        HOUR=$(printf "%02d" $((10#$h)))

        FILENAME="$YEAR-$MONTH-$DAY.$HOUR.pcap.gz"
        REMOTE_FILE="/data/$YEAR/$MONTH/$DAY/$FILENAME"
        LOCAL_FILE="$LOCAL_DEST_DIR/$FILENAME"

        # Check if the file already exists locally
        if [ -f "$LOCAL_FILE" ]; then
          echo "[~] Skipping: $FILENAME (Already exists locally)"
        else
          echo "[*] Copying: $REMOTE_FILE"

          # Perform the secure copy
          scp "$REMOTE_HOST:$REMOTE_FILE" "$LOCAL_DEST_DIR/"

          if [ $? -eq 0 ]; then
            echo "[+] Successfully copied to $LOCAL_DEST_DIR/"
          else
            echo "[-] Error/Warning: Failed to copy $REMOTE_FILE"
          fi
        fi
        echo "---------------------------------------------------"
      done
    done
  done
done

echo "[+] Automated PCAP copy pipeline completed!"
