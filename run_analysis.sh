#!/bin/bash

# Usage: ./run_analysis.sh 2024 01
# This script processes the first 7 days (1 week) of the specified month.

YEAR=$1
MONTH=$2

if [ -z "$MONTH" ]; then
  echo "Usage: ./run_analysis.sh <YYYY> <MM>"
  exit 1
fi

MMDB_PATH="./data/GeoLite2-Country.mmdb" # Ensure this path is correct

echo "[*] Starting 1-week batch processing for $YEAR-$MONTH"
echo "==================================================="

# Loop through days 01 to 07
for DAY in {01..07}; do

  DATA_DIR="/data/$YEAR/$MONTH/$DAY"
  OUTPUT_BASE="./analysis_results/$YEAR/$MONTH/$DAY"

  # Check if the data directory exists for this specific day
  if [ ! -d "$DATA_DIR" ]; then
    echo "[-] Directory $DATA_DIR does not exist. Skipping $YEAR-$MONTH-$DAY."
    continue
  fi

  # Check the year and use the appropriate GeoLite file
  if [ "$YEAR" == "2021" ]; then
    MMDB_PATH="./data/GeoLite2-Country-2021.mmdb"
  else
    MMDB_PATH="./data/GeoLite2-Country-2025.mmdb"
  fi

  echo "\n[*] Processing day: $YEAR-$MONTH-$DAY"
  echo "\n[*] Using GeoLite data: $MMDB_PATH"

  # Iterate over every compressed PCAP in the directory
  for pcap_file in "$DATA_DIR"/*.pcap.gz; do

    # Safety check in case the directory exists but is empty
    [ -e "$pcap_file" ] || continue

    # Extract just the filename (e.g., "2024-01-01.00")
    filename=$(basename -- "$pcap_file")
    base_name="${filename%.pcap.gz}"

    # Create a dedicated output folder for this specific hour
    HOUR_OUTDIR="$OUTPUT_BASE/$base_name"
    mkdir -p "$HOUR_OUTDIR"

    echo "---------------------------------------------------"
    echo "[*] Running pipeline on $filename ..."

    # Run the scripts sequentially
    python 1_pcap_overview.py -p "$pcap_file" -o "$HOUR_OUTDIR"
    python 2_ics_port_analysis.py -p "$pcap_file" -o "$HOUR_OUTDIR"
    python 3_entropy_burstiness.py -p "$pcap_file" -o "$HOUR_OUTDIR"
    python 4_geo_analysis.py -p "$pcap_file" -m "$MMDB_PATH" -o "$HOUR_OUTDIR"
    python 5_heatmap_port_time.py -p "$pcap_file" -o "$HOUR_OUTDIR"

  done
done

echo "==================================================="
echo "[*] 1-week processing successfully completed for $YEAR-$MONTH."
