#!/bin/bash

# Usage: ./run_yearly_analysis.sh <YEAR1> <YEAR2> "<TARGET_DAYS>" "<HOURS>" [MAX_PACKETS_PER_FILE]
# Example: ./run_yearly_analysis.sh 2021 2025 "15" "00 06 12 18" 2000000

YEAR1=$1
YEAR2=$2
TARGET_DAYS=$3
HOURS=$4
MAX_PACKETS=${5:-1000000} # Default to 1,000,000 if not provided

# Check if the minimum required arguments are provided
if [ -z "$HOURS" ]; then
  echo "Usage: ./run_yearly_analysis.sh <YEAR1> <YEAR2> \"<TARGET_DAYS>\" \"<HOURS>\" [MAX_PACKETS]"
  echo "Example: ./run_yearly_analysis.sh 2021 2025 \"15\" \"00 06 12 18\" 2000000"
  exit 1
fi

echo "[*] Starting YEARLY DISTRIBUTED batch processing for $YEAR1 vs $YEAR2"
echo "[*] Target Days per Month: $TARGET_DAYS"
echo "[*] Target Hours per Day: $HOURS"
echo "[*] Maximum packets PER FILE set to: $MAX_PACKETS"
echo "==================================================="

# Dynamically set the MMDB paths based on the requested years
MMDB_PATH1="./data/GeoLite2-Country-${YEAR1}.mmdb"
MMDB_PATH2="./data/GeoLite2-Country-${YEAR2}.mmdb"

# 1. Gather all target files from across all 12 months into single string variables
PCAP_LIST1=""
PCAP_LIST2=""

for MONTH in 01 02 03 04 05 06 07 08 09 10 11 12; do
  for d in $TARGET_DAYS; do
    DAY=$(printf "%02d" $((10#$d)))

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
done

# Check if we actually found files for both datasets
if [ -z "$PCAP_LIST1" ] || [ -z "$PCAP_LIST2" ]; then
  echo "[-] Critical Error: Missing PCAP files for one or both datasets. Cannot perform cross-year comparison."
  exit 1
fi

# 2. Create a single master output directory for the combined yearly results
OUTPUT_DIR="./analysis_results/${YEAR1}_vs_${YEAR2}_Yearly_Sample"
mkdir -p "$OUTPUT_DIR"

echo "---------------------------------------------------"
echo "[*] Running combined comparative pipeline on collected files..."
echo "[*] Outputting results to: $OUTPUT_DIR"
echo "---------------------------------------------------"
echo ""

# We define standard labels based on the years passed to the script
LABEL1="${YEAR1} Baseline"
LABEL2="${YEAR2} Bot Traffic"

# 3. Run the scripts using the unbuffered flag (-u) for real-time nohup logging
echo "---------------------------------------------------"
echo "[*] Running Script 1: 1_pcap_overview.py..."
echo "---------------------------------------------------"
python3 -u 1_pcap_overview.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
echo ""

echo "---------------------------------------------------"
echo "[*] Running Script 2: 2_ics_port_analysis.py..."
echo "---------------------------------------------------"
python3 -u 2_ics_port_analysis.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
echo ""

echo "---------------------------------------------------"
echo "[*] Running Script 3: 3_entropy_burstiness.py..."
echo "---------------------------------------------------"
python3 -u 3_entropy_burstiness.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
echo ""

echo "---------------------------------------------------"
echo "[*] Running Script 4: 4_geo_analysis.py..."
echo "---------------------------------------------------"
python3 -u 4_geo_analysis.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -m1 "$MMDB_PATH1" -m2 "$MMDB_PATH2" -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
echo ""

echo "---------------------------------------------------"
echo "[*] Running Script 5: 5_ics_volume_shifts.py..."
echo "---------------------------------------------------"
python3 -u 5_ics_volume_shifts.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
echo ""

echo "---------------------------------------------------"
echo "[*] Running Script 6: 6_ids_timeseries.py..."
echo "---------------------------------------------------"
python3 -u 6_ids_timeseries.py -p1 $PCAP_LIST1 -p2 $PCAP_LIST2 -l1 "$LABEL1" -l2 "$LABEL2" -o "$OUTPUT_DIR" -n "$MAX_PACKETS"
echo ""

echo "---------------------------------------------------"
echo "[*] Running Script 7: 7_evaluate_ids.py..."
echo "---------------------------------------------------"

BASELINE_CSV="$OUTPUT_DIR/${YEAR1}_baseline_ids_timeseries_1sec.csv"
TEST_CSV="$OUTPUT_DIR/${YEAR2}_bot_traffic_ids_timeseries_1sec.csv"

python3 -u 7_evaluate_ids.py -b "$BASELINE_CSV" -t "$TEST_CSV" -o "$OUTPUT_DIR" --baseline-label "$LABEL1" --test-label "$LABEL2"

echo ""
echo "==================================================="
echo "[+] Yearly distributed processing successfully completed!"
