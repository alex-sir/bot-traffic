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

- Create the `output` directory (Linux):

```bash
mkdir output
```

## Scripts

The project consists of five Python scripts which automate data engineering and
statistical analysis of the network telescope data.
Additionally, the bash script `run_analysis.sh` is provided to automate the
execution of all five Python scripts.

### Script 1 — `1_pcap_overview.py`

**Topic: Data Engineering**
Reads the PCAP file iteratively and produces a single, high-quality table summarizing core metrics of the network traffic, including data volume, average packet rates, and protocol distribution.
**Outputs:** `pcap_overview_table.png`

```bash
python 1_pcap_overview.py -p <pcap_file> -o <output_dir> -n <max_packets>
```

### Script 2 — `2_ics_port_analysis.py`

**Topic: Data Engineering**
Identifies traffic targeting known Industrial Control System (ICS) ports and determines the scanning pattern (Sequential vs. Random) based on destination IP gaps. Produces an annotated horizontal bar chart.
**Outputs:** `ics_port_analysis.png`

```bash
python 2_ics_port_analysis.py -p <pcap_file> -o <output_dir> -n <max_packets>
```

### Script 3 — `3_entropy_burstiness.py`

**Topic: Statistical Analysis**
Calculates mathematically reliable metrics for network telescope traffic. Computes global Shannon Entropy for Source IPs/Destination Ports and Inter-Arrival Time (IAT) to determine traffic burstiness.
**Outputs:** `entropy_diversity.png`, `burstiness_iat.png`

```bash
python 3_entropy_burstiness.py -p <pcap_file> -o <output_dir> -n <max_packets>
```

### Script 4 — `4_geo_analysis.py`

**Topic: Statistical Analysis**
Maps source IPs to countries using a [MaxMind DB file](https://maxmind.github.io/MaxMind-DB). Produces a high-resolution horizontal bar chart annotated with total packet counts and unique IPs per country.
**Outputs:** `geo_country_bar.png`

```bash
python 4_geo_analysis.py -p <pcap_file> -m <mmdb_file> -o <output_dir> -n <max_packets>
```

### Script 5 — `5_heatmap_port_time.py`

**Topic: Statistical Analysis**
Builds an explicitly defined, high-resolution matrix heatmap showing packet activity on key ICS/OT ports across 1-minute time bins.
**Outputs:** `port_heatmap_matrix.png`, `port_heatmap_data.csv`

```bash
python 5_heatmap_port_time.py -p <pcap_file> -o <output_dir> -n <max_packets>
```

### Bash Script — `run_analysis.sh`

**NOTE: This script must be run within a Merit VM.**

Iterates through the specified days of data of the specified month.
It runs all five Python scripts on the specified PCAP hours, saving the
output into organized folders.

```bash
./run_analysis.sh <YYYY> <MM> <START_DAY> <END_DAY> "<HOURS>" [MAX_PACKETS]
```

---

## Output Files Summary

| File                      | Produced by | Description                                      |
| ------------------------- | ----------- | ------------------------------------------------ |
| `pcap_overview_table.png` | Script 1    | Core metrics and basic statistics summary table  |
| `ics_port_analysis.png`   | Script 2    | ICS port targeting and scanning pattern chart    |
| `entropy_diversity.png`   | Script 3    | Global Shannon entropy chart (Actual vs Maximum) |
| `burstiness_iat.png`      | Script 3    | Inter-Arrival Time (IAT) distribution histogram  |
| `geo_country_bar.png`     | Script 4    | Top source countries bar chart with IP counts    |
| `port_heatmap_matrix.png` | Script 5    | Annotated ICS port activity matrix               |
| `port_heatmap_data.csv`   | Script 5    | Raw CSV data for the heatmap matrix              |

---

## Recommended Run Order

1. Script 1 (orientation, sanity check)
2. Script 2 (ICS targeting findings)
3. Script 3 (entropy/burstiness metrics)
4. Script 4 (geo analysis)
5. Script 5 (heatmap visualization)

The bash script `run_analysis.sh` runs the Python scripts in
this order.

## Contributors

- Alex Carbajal ([alex-sir](https://github.com/alex-sir))
- Jonahtan Vasquez ([JonahtanV](https://github.com/JonahtanV))
- Caleb Faultersack ([MrZergon](https://github.com/MrZergon))
