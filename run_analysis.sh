#!/bin/bash

# Usage: ./run_analysis.sh <YYYY> <MM> <START_DAY> <END_DAY> "<HOURS>" [MAX_PACKETS_PER_FILE]
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

echo "[*] Starting AGGREGATED batch processing for $YEAR-$MONTH"
echo "[*] Days Range: $START_DAY to $END_DAY"
echo "[*] Target Hours: $HOURS"
echo "[*] Maximum packets PER FILE set to: $MAX_PACKETS"
echo "==================================================="

# Check the year and use the appropriate GeoLite file
if [ "$YEAR" == "2021" ]; then
  MMDB_PATH="./data/GeoLite2-Country-2021.mmdb"
else
  MMDB_PATH="./data/GeoLite2-Country-2025.mmdb"
fi

# 1. Gather all target files into a single string variable
PCAP_LIST=""

for ((d = 10#$START_DAY; d <= 10#$END_DAY; d++)); do
  DAY=$(printf "%02d" $d)
  DATA_DIR="/data/$YEAR/$MONTH/$DAY"

  for h in $HOURS; do
    HOUR=$(printf "%02d" $((10#$h)))
    pcap_file="$DATA_DIR/$YEAR-$MONTH-$DAY.$HOUR.pcap.gz"

    if [ -f "$pcap_file" ]; then
      PCAP_LIST="$PCAP_LIST $pcap_file"
    else
      echo "[-] Warning: $pcap_file not found. Skipping in aggregation."
    fi
  done
done

# Check if we actually found any files
if [ -z "$PCAP_LIST" ]; then
  echo "[-] Critical Error: No matching PCAP files found for the given parameters."
  exit 1
fi

# 2. Create a single master output directory for the combined results
OUTPUT_DIR="./analysis_results/${YEAR}_${MONTH}_combined"
mkdir -p "$OUTPUT_DIR"

echo "---------------------------------------------------"
echo "[*] Running combined pipeline on all collected files..."
echo "[*] Outputting results to: $OUTPUT_DIR"
echo "---------------------------------------------------"

# 3. Run the scripts ONCE, passing the entire list of files at the same time
python 1_pcap_overview.py -p "$PCAP_LIST" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
python 2_ics_port_analysis.py -p "$PCAP_LIST" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
python 3_entropy_burstiness.py -p "$PCAP_LIST" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
python 4_geo_analysis.py -p "$PCAP_LIST" -m "$MMDB_PATH" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
python 5_heatmap_port_time.py -p "$PCAP_LIST" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
python 6_ids_timeseries.py -p "$PCAP_LIST" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"

echo "==================================================="
echo "[*] Combined processing successfully completed!"
