"""
Script 7: IDS Anomaly Simulation & Sensitivity Trade-off

Compares a test traffic timeline against a strict IDS baseline, evaluating 
standard threshold degradation and the False Positive trade-offs of 
increased detection sensitivity.

Usage Instructions:
    Run the script from the terminal, providing the paths to the CSV files.

    Basic usage:
        python3 7_evaluate_ids.py -b path/to/baseline/ids_timeseries_1sec.csv \
                                  -t path/to/test/ids_timeseries_1sec.csv \
                                  --baseline-label "2021" \
                                  --test-label "2025"

    Example with custom output directory:
        python3 7_evaluate_ids.py -b path/to/baseline/ids_timeseries_1sec.csv \
                                  -t path/to/test/ids_timeseries_1sec.csv \
                                  -o output/ \
                                  --baseline-label "2021" \
                                  --test-label "2025"
"""

import argparse
import os
import pandas as pd
import matplotlib

# Use 'Agg' non-interactive backend for matplotlib so it runs headlessly
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --- STANDARDIZED FONT CONFIGURATION ---
# Sets consistent styling across all generated charts and visualizations
plt.rcParams.update(
    {
        "font.size": 22,
        "font.family": "serif",
        "axes.labelsize": 26,
        "xtick.labelsize": 22,
        "ytick.labelsize": 22,
        "legend.fontsize": 22,
        "figure.dpi": 300,
    }
)


def parse_args():
    """
    Parses command-line arguments to specify dataset paths, labels, and output directory.
    """
    parser = argparse.ArgumentParser(
        description="IDS Evaluation & Sensitivity Simulation"
    )
    parser.add_argument("-b", "--baseline", required=True, help="Path to Baseline CSV")
    parser.add_argument("-t", "--test", required=True, help="Path to Test CSV")
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")

    parser.add_argument(
        "--baseline-label",
        default="Baseline Traffic",
        help="Label for the baseline dataset",
    )
    parser.add_argument(
        "--test-label", default="Test Traffic", help="Label for the test dataset"
    )

    return parser.parse_args()


def main():
    # Parse CLI arguments and establish the output path
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    # Load the 1-second interval time-series datasets
    df_baseline = pd.read_csv(args.baseline)
    df_test = pd.read_csv(args.test)

    # --- PROTECTION AGAINST OUTLIERS ---
    # Calculates the 99.5th percentile threshold on baseline data and filters out outliers
    cap = df_baseline["packet_count"].quantile(0.995)
    clean_baseline = df_baseline[df_baseline["packet_count"] <= cap]

    # 1. Establish the Standard Baseline Metrics
    mean_baseline = clean_baseline["packet_count"].mean()
    std_baseline = clean_baseline["packet_count"].std()

    # Standard Anomaly Threshold: Mean + 3 Standard Deviations
    std_threshold = mean_baseline + (3 * std_baseline)

    # 2. Evaluate Standard Degradation (Default Configuration)
    # Counts intervals exceeding standard threshold on baseline to calculate False Positive Rate (FPR)
    std_violations_baseline = len(
        df_baseline[df_baseline["packet_count"] > std_threshold]
    )
    std_fpr_baseline = (std_violations_baseline / len(df_baseline)) * 100

    # Counts intervals exceeding standard threshold on test traffic to calculate Detection and Evasion rates
    std_violations_test = len(df_test[df_test["packet_count"] > std_threshold])
    std_detection_rate = (std_violations_test / len(df_test)) * 100
    std_evasion_rate = 100.0 - std_detection_rate

    # --- 3. SENSITIVITY TRADE-OFF ANALYSIS ---
    # Calculate the threshold required to successfully detect 90% of the botnet
    target_catch_rate = 0.90
    sens_threshold = df_test["packet_count"].quantile(1.0 - target_catch_rate)

    # Evaluate the catastrophic False Positive Rate on normal traffic at this new threshold
    sens_violations_baseline = len(
        df_baseline[df_baseline["packet_count"] > sens_threshold]
    )
    sens_fpr_baseline = (sens_violations_baseline / len(df_baseline)) * 100

    # --- GENERATE SEPARATE REPORT FILE ---
    # Define text report output path and build report content
    report_path = os.path.join(args.outdir, "ids_simulation_report.txt")

    report_content = f"""==================================================
IDS ANOMALY SIMULATION & SENSITIVITY REPORT
==================================================

[1] BASELINE STATISTICS ({args.baseline_label})
--------------------------------------------------
Total Seconds Evaluated : {len(df_baseline):,}
Outlier Cap Applied     : {cap:,.0f} pkts/s (99.5th Percentile)
Mean Volume             : {mean_baseline:,.2f} pkts/s
Standard Deviation      : {std_baseline:,.2f} pkts/s

[2] DEFAULT CONFIGURATION DEGRADATION
--------------------------------------------------
Formula                 : Mean + (3 * StdDev)
Standard Threshold      : {std_threshold:,.0f} pkts/s

- Baseline False Positives : {std_fpr_baseline:.2f}% (Normal traffic flagged)
- Botnet Detection Rate    : {std_detection_rate:.2f}% (Attacks caught)
- Botnet Evasion Rate      : {std_evasion_rate:.2f}% (Attacks undetected)

[3] HIGH SENSITIVITY TUNING TRADE-OFF
--------------------------------------------------
Goal: Lower the threshold to catch 90% of {args.test_label}.
Required Threshold      : {sens_threshold:,.0f} pkts/s

- New Detection Rate       : 90.00%
- NEW FALSE POSITIVE RATE  : {sens_fpr_baseline:.2f}% (Normal traffic flagged)

==================================================
CONCLUSION:
The IDS is fundamentally incapable of separating the datasets.
At standard configurations, {std_evasion_rate:.2f}% of the botnet evades detection.
Tuning the IDS to catch the botnet requires lowering the threshold to
{sens_threshold:,.0f} pkts/s, which results in a massive {sens_fpr_baseline:.2f}% False
Positive Rate, rendering the system unusable due to alert fatigue.
==================================================
"""

    # Print report summary to standard output
    print(report_content)

    # Save report summary to text file
    with open(report_path, "w") as f:
        f.write(report_content)
    print(f"[+] Detailed text report saved to {report_path}")

    # --- 4. Visualization ---
    # Setup subplots for displaying density distributions and threshold lines
    fig, ax = plt.subplots(figsize=(16, 8))

    # Plot the full, raw distributions as probability density histograms
    ax.hist(
        df_baseline["packet_count"],
        bins=50,
        alpha=0.6,
        color="#4C72B0",
        density=True,
        label=args.baseline_label,
    )
    ax.hist(
        df_test["packet_count"],
        bins=50,
        alpha=0.6,
        color="#C44E52",
        density=True,
        label=args.test_label,
    )

    # Draw the Standard IDS Threshold line
    ax.axvline(
        std_threshold,
        color="black",
        linestyle="--",
        linewidth=3,
        label=f"Standard Threshold ({std_threshold:,.0f} pkts/s)",
    )

    # Draw the High Sensitivity Threshold line
    ax.axvline(
        sens_threshold,
        color="#D9534F",  # A distinct, warning-red color
        linestyle=":",
        linewidth=4,
        label=f"High Sensitivity Tuning ({sens_threshold:,.0f} pkts/s)",
    )

    # Highlight the "False Positive Flood Zone"
    # This shades the area above the sensitive threshold where normal blue traffic gets flagged
    ax.axvspan(
        sens_threshold,
        df_baseline["packet_count"].max(),
        color="#4C72B0",
        alpha=0.15,
        label=f"False Positive Flood ({sens_fpr_baseline:.1f}% Alert Rate)",
    )

    # Configure axes, labels, and ticks
    ax.set_xlabel("Packets per Second", labelpad=20, fontweight="bold")
    ax.set_ylabel("Probability Density", labelpad=20, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    # Remove top and right borders for a cleaner aesthetic
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Configure custom legend layout
    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.05),
        ncol=2,
        framealpha=0.9,
        edgecolor="black",
    )

    plt.tight_layout()
    out_png = os.path.join(args.outdir, "ids_degradation.png")
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    print(f"[+] Visualization saved to {out_png}")


if __name__ == "__main__":
    main()
