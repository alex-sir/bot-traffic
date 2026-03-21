# Characterizing the Impact of AI-Generated and Automated Bot Traffic on Network Behavior and Security

## Development Setup

This project utilizes Python scripts and a Python virtual environment.

- Ensure Python 3.8+ is installed:

```bash
python -V
```

- Create a virtual environment for the project:

Linux/macOS:

```bash
python3 -m venv .venv
```

Windows:

```bash
py -m venv .venv
```

- Activate the virtual environment:

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```bash
.venv/Scripts/activate
```

- Install the project packages with pip:

```bash
pip install -r requirements.txt
```

- Deactivate the virtual environment when done:

```bash
deactivate
```

### How to Add New Project Packages

First, make sure the virtual environment is active. Then, write all installed packages to `requirements.txt`:

```bash
pip freeze > requirements.txt
```

## Data Setup

You need to add your own data sets to use with the Python scripts. Data should be
placed in the `data` directory that is created within this project.

- Create the `data` directory (Linux):

```bash
mkdir data
```

Now, just copy all of your data files to this directory (`.pcap`, `.mmdb`, etc).

## Output Setup

The scripts produce output files (`.csv`, `.png`, etc), so a directory is required
to store these files. Output files should be stored in the `output` directory
that is created within this project.

- Create the `output` directory (Linux):

```bash
mkdir output
```

## Scripts

### Script 1 — `1_pcap_overview.py`

**Topic: Data Engineering**
High-level PCAP summary: total packets, protocol breakdown, time range, top source IPs and destination ports.

```bash
python 1_pcap_overview.py
```

### Script 2 — `2_ics_port_analysis.py`

**Topic: Data Engineering**
ICS/OT port targeting analysis: flags Modbus, DNP3, EtherNet/IP, etc. Measures unique source IPs and detects sequential vs. random scanning patterns.

```bash
python 2_ics_port_analysis.py
```

### Script 3 — `3_entropy_burstiness.py`

**Topic: Statistical Analysis**
Computes Shannon entropy (src IP, dst port, protocol) and packet rate per 1-minute bin. Calculates burstiness (CV) and Hurst exponent.
Outputs: `entropy_burstiness.csv`, `entropy_burstiness.png`

```bash
python 3_entropy_burstiness.py
```

### Script 4 — `4_geo_analysis.py`

**Topic: Statistical Analysis**
Maps source IPs to countries using a [MaxMind DB file](https://maxmind.github.io/MaxMind-DB). Produces top-20 country table and bar chart.
Outputs: `geo_country_stats.csv`, `geo_country_bar.png`

```bash
python 4_geo_analysis.py
```

### Script 5 — `5_heatmap_port_time.py`

**Topic: Statistical Analysis**
Builds a port-activity heatmap over time for ICS and common scanning ports.
Outputs: `port_heatmap.png`, `port_heatmap_data.csv`

```bash
python 5_heatmap_port_time.py
```

---

## Output Files Summary

| File                   | Produced by |
| ---------------------- | ----------- |
| entropy_burstiness.csv | Script 3    |
| entropy_burstiness.png | Script 3    |
| geo_country_stats.csv  | Script 4    |
| geo_country_bar.png    | Script 4    |
| port_heatmap.png       | Script 5    |
| port_heatmap_data.csv  | Script 5    |

---

## Recommended Run Order

1. Script 1 (orientation, sanity check)
2. Script 2 (ICS targeting findings)
3. Script 3 (entropy/burstiness metrics)
4. Script 4 (geo analysis)
5. Script 5 (heatmap visualization)

## Contributors

- Alex Carbajal ([alex-sir](https://github.com/alex-sir))
- Jonahtan Vasquez ([JonahtanV](https://github.com/JonahtanV))
- Caleb Faultersack ([MrZergon](https://github.com/MrZergon))
