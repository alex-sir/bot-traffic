# Characterizing AI-Assisted Bot Traffic in Darknet Data: Implications for ICS and IIoT Security

## Development Setup

This project utilizes Python scripts and a Python virtual environment.
Python packages are managed using **pip**.

Ensure Python 3.8+ is installed:

```bash
python -V
```

Ensure pip is installed:

```bash
pip -V
```

Create a virtual environment for the project:

Linux/macOS

```bash
python3 -m venv .venv
```

Windows

```bash
py -m venv .venv
```

Activate the virtual environment:

Linux/macOS

```bash
source .venv/bin/activate
```

Windows

```bash
.venv/Scripts/activate
```

Install the project packages with pip:

```bash
pip install -r requirements.txt
```

Deactivate the virtual environment when done:

```bash
deactivate
```

### How to Add New Project Packages

First, make sure the virtual environment is active. Then, write all installed packages to `requirements.txt`:

```bash
pip freeze > requirements.txt
```

## Data Analysis

Data analysis for the bot traffic is performed using [Merit's network telescope data](https://www.merit.edu/research/projects/orion-network-telescope). A virtual machine (VM) provided by Merit is connected to remotely using SSH. Merit's data is organized in the `/data` directory in the VM and is subdivided as follows:

- `/data/YYYY/MM/DD/`

Due to the sheer size of the data, it is not recommended to copy over the data for local use.
Instead, run the analysis within the VM, and then copy the results to your local machine
for further analysis.

### Copy Remote Data Locally

To copy data from a remote file in the Merit VM to your local machine:

```bash
scp merit-vm:/path/to/bot-traffic/data-file ./local-directory
```

To recursively copy data from a remote directory in the Merit VM
to your local machine:

```bash
scp -r merit-vm:/path/to/bot-traffic/data-directory ./local-directory
```

### Copy This Repository to Merit VM

The Merit VM does not have Git installed. Though, it does have basic GNU utilities.

To copy the latest version of the main branch as a tarball
(**run within the Merit VM**):

```bash
wget https://github.com/alex-sir/bot-traffic/archive/main.tar.gz
```

Then, extract the tarball:

```bash
tar -xzvf main.tar.gz
```

You can also copy over your local version of the repository using `scp`:

```bash
scp -r ./bot-traffic merit-vm:~/code
```

## How to Run the Python Scripts in Merit VM

Installation of the packages required to run the scripts requires the use of
**pip**. Since pip is not installed in the Merit VM, we will instead use
**Miniconda**. This downloads a completely isolated version of Python and pip
into your user folder. Follow these steps to set up Miniconda:

Download the Miniconda installer:

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
```

Run the installer into your home directory:

```bash
bash Miniconda3-latest-Linux-x86_64.sh -b -p $HOME/miniconda
```

Activate the isolated environment:

```bash
source $HOME/miniconda/bin/activate
```

Install the required packages (run in the root project directory):

```bash
pip install -r requirements.txt
```

## Test Data Setup

It is preferable to test out the scripts and analysis with local data first.
If so, you need to add your own data sets to use with the Python scripts. Place
data files in the `data` directory within this project.

Create the `data` directory (Linux):

```bash
mkdir data
```

Now, just copy all of your data files to this directory (`.pcap`, `.mmdb`, etc).

## Output Setup

The scripts produce output files (`.png`, `.csv`), so a directory is required
to store these files. Store output files in the `output` directory within this project.

Create the `output` directory (Linux):

```bash
mkdir output
```

If the `output` directory does not exist once you start running the Python scripts,
it is created automatically by the scripts.

## Scripts

The project consists of seven Python scripts which automate data engineering and
statistical analysis of the network telescope data. Because the pipeline is
designed to perform longitudinal (cross-year) comparisons, all of the scripts
require providing two distinct datasets simultaneously to generate comparative
visualizations and tables.

### Script 1 — `1_pcap_overview.py`

**Topic: Data Engineering**
Reads two distinct sets of PCAP files iteratively and produces a single, high-quality, combined comparison table summarizing core metrics of the network traffic, including data volume, average packet rates, and the dominant ICS protocol.
**Outputs:** `pcap_overview.png`

```bash
python3 1_pcap_overview.py -p1 <pcap_dir1> -p2 <pcap_dir2> -l1 "Baseline Traffic" -l2 "Test Traffic" -o <output_dir> -n <max_packets>
```

### Script 2 — `2_ics_port_analysis.py`

**Topic: Data Engineering**
Identifies traffic targeting known Industrial Control System (ICS) ports and determines the scanning pattern (Sequential vs. Random) based on destination IP gaps using a dynamically scaling threshold. Produces an overlaid grouped horizontal bar chart.
**Outputs:** `ics_ports.png`

```bash
python3 2_ics_port_analysis.py -p1 <pcap_dir1> -p2 <pcap_dir2> -l1 "Baseline Traffic" -l2 "Test Traffic" -o <output_dir> -n <max_packets>
```

### Script 3 — `3_entropy_burstiness.py`

**Topic: Statistical Analysis**
Calculates statistical metrics across both datasets. Outputs a grouped bar chart for global Shannon Entropy (Source IPs/Destination Ports) and an overlaid Inter-Arrival Time (IAT) histogram to visually contrast traffic burstiness.
**Outputs:** `entropy.png`, `burstiness.png`

```bash
python3 3_entropy_burstiness.py -p1 <pcap_dir1> -p2 <pcap_dir2> -l1 "Baseline Traffic" -l2 "Test Traffic" -o <output_dir> -n <max_packets>
```

### Script 4 — `4_geo_analysis.py`

**Topic: Statistical Analysis**
Maps source IPs to countries using MaxMind DB files for their respective years. Produces a dense analytical table comparing the top source countries across both datasets, explicitly calculating the percent shift (Δ) in volume.
**Outputs:** `geo_analysis.png`

```bash
python3 4_geo_analysis.py -p1 <pcap_dir1> -p2 <pcap_dir2> -m1 <mmdb_file1> -m2 <mmdb_file2> -l1 "Baseline Traffic" -l2 "Test Traffic" -o <output_dir> -n <max_packets>
```

### Script 5 — `5_heatmap_port_time.py`

**Topic: Statistical Analysis**
Builds an explicitly defined, high-resolution Delta "Difference Matrix" heatmap. It aligns both captures to relative time, subtracts the traffic volume of the baseline from the newer dataset, and highlights surges or drops in activity specifically on ICS ports.
**Outputs:** `ics_heatmap_delta.png`, `ics_heatmap_delta.csv`

```bash
python3 5_heatmap_port_time.py -p1 <pcap_dir1> -p2 <pcap_dir2> -l1 "Baseline Traffic" -l2 "Test Traffic" -o <output_dir> -n <max_packets>
```

### Script 6 — `6_ids_timeseries.py`

**Topic: Anomaly-Based IDS Simulation**
Extracts the raw packet volume per 1-second interval across two distinct sets of PCAP files.
This generates the foundational CSV data needed for both datasets to simulate an anomaly-based IDS in Script 7.
**Outputs:** `<label1>_ids_timeseries_1sec.csv`, `<label2>_ids_timeseries_1sec.csv`

```bash
python3 6_ids_timeseries.py -p1 <pcap_dir1> -p2 <pcap_dir2> -l1 "Baseline Traffic" -l2 "Test Traffic" -o <output_dir> -n <max_packets>
```

### Script 7 — `7_evaluate_ids.py`

**Topic: Anomaly-Based IDS Simulation**
Compares a test traffic timeline against a strict IDS baseline established by
historical traffic, proving the degradation of standard thresholding.
**Outputs:** `ids_degradation.png`

```bash
python3 7_evaluate_ids.py -b <baseline_csv> -t <test_csv> -o <output_dir> --baseline-label "Baseline Traffic" --test-label "Test Traffic"
```

### Bash Script — `run_analysis.sh`

**NOTE: This script must be run within a Merit VM.**

Iterates through the specified days of data of the specified month for two different years.
It runs Python scripts 1-7 on the specified PCAP hours, feeding both datasets simultaneously to generate comparative outputs.

When this script runs, it automatically creates the directory `analysis_results` (if it does not exist) within the project root directory.
This directory holds the subdirectories containing the comparative results (e.g., `2021_vs_2025_03_combined`).
All of the `.png` and `.csv` files that are generated are located within their respective subdirectory.

```bash
./run_analysis.sh <YEAR1> <YEAR2> <MM> <START_DAY> <END_DAY> "<HOURS>" [MAX_PACKETS]
```

---

## Output Files Summary

| File                              | Produced by | Description                                                   |
| --------------------------------- | ----------- | ------------------------------------------------------------- |
| `pcap_overview.png`               | Script 1    | Cross-Year core metrics and statistics summary table          |
| `ics_ports.png`                   | Script 2    | Grouped cross-year ICS port targeting and scanning chart      |
| `entropy.png`                     | Script 3    | Grouped cross-year Shannon entropy bar chart                  |
| `burstiness.png`                  | Script 3    | Overlaid cross-year Inter-Arrival Time (IAT) histogram        |
| `geo_analysis.png`                | Script 4    | Cross-Year geographic shift table tracking volume delta       |
| `ics_heatmap_delta.png`           | Script 5    | Delta "Difference Matrix" heatmap for ICS port activity       |
| `ics_heatmap_delta.csv`           | Script 5    | Raw CSV data backing the delta heatmap matrix                 |
| `<label>_ids_timeseries_1sec.csv` | Script 6    | Raw CSV time-series data for both datasets for IDS simulation |
| `ids_degradation.png`             | Script 7    | Cross-Year IDS anomaly simulation results and threshold chart |

---

## Recommended Run Order

1. Script 1 (orientation, data volume)
2. Script 2 (ICS targeting and gap findings)
3. Script 3 (entropy and burstiness distribution metrics)
4. Script 4 (geo analysis table and delta shift)
5. Script 5 (delta heatmap visualization)
6. Script 6 (IDS time-series data)
7. Script 7 (IDS simulation results)

The bash script `run_analysis.sh` runs Python scripts 1-7 simultaneously on both datasets in
this order.

## Contributors

- Alex Carbajal ([alex-sir](https://github.com/alex-sir))
- Jonahtan Vasquez ([JonahtanV](https://github.com/JonahtanV))
- Caleb Faultersack ([MrZergon](https://github.com/MrZergon))
