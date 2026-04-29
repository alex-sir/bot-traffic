#!/bin/bash

# Usage: ./run_analysis.sh <YYYY> <MM> <START_DAY> <END_DAY> "<HOURS>" [MAX_PACKETS]
# Example: ./run_analysis.sh 2021 03 01 07 "00 12" 71500000

YEAR=$1
MONTH=$2
START_DAY=$3
END_DAY=$4
HOURS=$5
MAX_PACKETS=${6:-1000000} # Default to 1,000,000 if not provided

# Check if the minimum required arguments are provided
if [ -z "$HOURS" ]; then
  echo "Usage: ./run_analysis.sh <YYYY> <MM> <START_DAY> <END_DAY> \"<HOURS>\" [MAX_PACKETS]"
  echo "Example: ./run_analysis.sh 2021 03 01 07 \"00 12\" 71500000"
  exit 1
fi

echo "[*] Starting batch processing for $YEAR-$MONTH"
echo "[*] Days Range: $START_DAY to $END_DAY"
echo "[*] Target Hours: $HOURS"
echo "[*] Maximum packets per file set to: $MAX_PACKETS"
echo "==================================================="

# Loop through the days, forcing base-10 to prevent octal errors on zero-padded numbers
for ((d = 10#$START_DAY; d <= 10#$END_DAY; d++)); do

  # Ensure the day variable is always two digits (e.g., 01, 02)
  DAY=$(printf "%02d" $d)

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

  echo -e "\n[*] Processing day: $YEAR-$MONTH-$DAY"
  echo "[*] Using GeoLite data: $MMDB_PATH"

  # Iterate ONLY over the specific hours provided by the user
  for h in $HOURS; do

    # Ensure the hour variable is always two digits (handles inputs like "0" or "00" cleanly)
    HOUR=$(printf "%02d" $((10#$h)))
    pcap_file="$DATA_DIR/$YEAR-$MONTH-$DAY.$HOUR.pcap.gz"

    # Check if the exact target file exists
    if [ ! -f "$pcap_file" ]; then
      echo "[-] File $pcap_file not found. Skipping."
      continue
    fi

    # Extract base names for output folders
    filename=$(basename -- "$pcap_file")
    base_name="${filename%.pcap.gz}"

    # Create a dedicated output folder for this specific hour
    HOUR_OUTDIR="$OUTPUT_BASE/$base_name"
    mkdir -p "$HOUR_OUTDIR"

    echo "---------------------------------------------------"
    echo "[*] Running pipeline on $filename (Cap: $MAX_PACKETS packets)..."

    # Run the scripts sequentially
    python 1_pcap_overview.py -p "$pcap_file" -o "$HOUR_OUTDIR" -n "$MAX_PACKETS"
    python 2_ics_port_analysis.py -p "$pcap_file" -o "$HOUR_OUTDIR" -n "$MAX_PACKETS"
    python 3_entropy_burstiness.py -p "$pcap_file" -o "$HOUR_OUTDIR" -n "$MAX_PACKETS"
    python 4_geo_analysis.py -p "$pcap_file" -m "$MMDB_PATH" -o "$HOUR_OUTDIR" -n "$MAX_PACKETS"
    python 5_heatmap_port_time.py -p "$pcap_file" -o "$HOUR_OUTDIR" -n "$MAX_PACKETS"

  done
done

echo "==================================================="
echo "[*] Processing successfully completed for $YEAR-$MONTH ($START_DAY to $END_DAY)."
