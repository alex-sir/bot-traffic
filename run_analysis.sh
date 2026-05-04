#!/bin/bash

# Usage: ./run_analysis.sh <YEAR1> <YEAR2> <MM> <START_DAY> <END_DAY> "<HOURS>" [MAX_PACKETS_PER_FILE]
# Example: ./run_analysis.sh 2021 2025 03 01 07 "00 12" 71500000

YEAR1=$1
YEAR2=$2
MONTH=$3
START_DAY=$4
END_DAY=$5
HOURS=$6
MAX_PACKETS=${7:-1000000} # Default to 1,000,000 if not provided

# Check if the minimum required arguments are provided
if [ -z "$HOURS" ]; then
  echo "Usage: ./run_analysis.sh <YEAR1> <YEAR2> <MM> <START_DAY> <END_DAY> \"<HOURS>\" [MAX_PACKETS]"
  echo "Example: ./run_analysis.sh 2021 2025 03 01 07 \"00 12\" 71500000"
  exit 1
fi

echo "[*] Starting CROSS-YEAR AGGREGATED batch processing for $YEAR1 vs $YEAR2 ($MONTH)"
echo "[*] Days Range: $START_DAY to $END_DAY"
echo "[*] Target Hours: $HOURS"
echo "[*] Maximum packets PER FILE set to: $MAX_PACKETS"
echo "==================================================="

# Dynamically set the MMDB paths based on the requested years
MMDB_PATH1="./data/GeoLite2-Country-${YEAR1}.mmdb"
MMDB_PATH2="./data/GeoLite2-Country-${YEAR2}.mmdb"

# 1. Gather all target files into single string variables for each dataset
PCAP_LIST1=""
PCAP_LIST2=""

for ((d = 10#$START_DAY; d <= 10#$END_DAY; d++)); do
  DAY=$(printf "%02d" $d)

  DATA_DIR1="/data/$YEAR1/$MONTH/$DAY"
  DATA_DIR2="/data/$YEAR2/$MONTH/$DAY"

  for h in $HOURS; do
    HOUR=$(printf "%02d" $((10#$h)))

    pcap_file1="$DATA_DIR1/$YEAR1-$MONTH-$DAY.$HOUR.pcap.gz"
    pcap_file2="$DATA_DIR2/$YEAR2-$MONTH-$DAY.$HOUR.pcap.gz"

    # Check and append Year 1 files
    if [ -f "$pcap_file1" ]; then
      PCAP_LIST1="$PCAP_LIST1 $pcap_file1"
    else
      echo "[-] Warning: $pcap_file1 not found. Skipping."
    fi

    # Check and append Year 2 files
    if [ -f "$pcap_file2" ]; then
      PCAP_LIST2="$PCAP_LIST2 $pcap_file2"
    else
      echo "[-] Warning: $pcap_file2 not found. Skipping."
    fi
  done
done

# Check if we actually found files for both datasets
if [ -z "$PCAP_LIST1" ] || [ -z "$PCAP_LIST2" ]; then
  echo "[-] Critical Error: Missing PCAP files for one or both datasets. Cannot perform cross-year comparison."
  exit 1
fi

# 2. Create a single master output directory for the combined results
OUTPUT_DIR="./analysis_results/${YEAR1}_vs_${YEAR2}_${MONTH}_combined"
mkdir -p "$OUTPUT_DIR"

echo "---------------------------------------------------"
echo "[*] Running combined comparative pipeline on collected files..."
echo "[*] Outputting results to: $OUTPUT_DIR"
echo "---------------------------------------------------"

# We define standard labels based on the years passed to the script
LABEL1="${YEAR1} Baseline"
LABEL2="${YEAR2} Bot Traffic"

# 3. Run the scripts, passing both datasets and their labels simultaneously
# Note: PCAP variables are intentionally unquoted to allow argparse nargs='+' to read them as lists
python3 1_pcap_overview.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"

python3 2_ics_port_analysis.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"

python3 3_entropy_burstiness.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"

python3 4_geo_analysis.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -m1 "$MMDB_PATH1" -m2 "$MMDB_PATH2" -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"

python3 5_heatmap_port_time.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"

python3 6_ids_timeseries.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"

# 4. Automatically run Script 7 using the dynamically generated CSV files
echo "---------------------------------------------------"
echo "[*] Running IDS Anomaly Simulation (Script 7)..."
echo "---------------------------------------------------"

# Predict the exact file names Script 6 just generated
BASELINE_CSV="$OUTPUT_DIR/${YEAR1}_baseline_ids_timeseries_1sec.csv"
TEST_CSV="$OUTPUT_DIR/${YEAR2}_bot_traffic_ids_timeseries_1sec.csv"

python3 7_evaluate_ids.py -b "$BASELINE_CSV" -t "$TEST_CSV" -o "$OUTPUT_DIR" --baseline-label "$LABEL1" --test-label "$LABEL2"

echo "==================================================="
echo "[+] Combined processing successfully completed!"
