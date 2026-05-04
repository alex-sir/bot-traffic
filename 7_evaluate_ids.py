"""
Script 7: IDS Anomaly Simulation

Compares a test traffic timeline against a strict IDS baseline
established by historical traffic, proving the degradation of standard thresholding.

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
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --- STANDARDIZED FONT CONFIGURATION ---
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
    parser = argparse.ArgumentParser(description="IDS Evaluation Simulation")
    parser.add_argument("-b", "--baseline", required=True, help="Path to Baseline CSV")
    parser.add_argument("-t", "--test", required=True, help="Path to Test CSV")
    parser.add_argument("-o", "--outdir", default="output", help="Output directory")

    # Dynamic labels for graph legends and terminal output
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
    args = parse_args()

    # Load the data
    df_baseline = pd.read_csv(args.baseline)
    df_test = pd.read_csv(args.test)

    # --- PROTECTION AGAINST OUTLIERS ---
    # Calculate the 99.5th percentile to identify extreme anomalous spikes.
    # We drop these temporarily so they don't artificially inflate the standard deviation.
    cap = df_baseline["packet_count"].quantile(0.995)
    clean_baseline = df_baseline[df_baseline["packet_count"] <= cap]

    # 1. Establish the Baseline Metrics on the CLEAN dataset
    mean_baseline = clean_baseline["packet_count"].mean()
    std_baseline = clean_baseline["packet_count"].std()

    # Anomaly Threshold: 99.7% confidence interval (Mean + 3 Standard Deviations)
    threshold = mean_baseline + (3 * std_baseline)

    # 2. Evaluate Degradation
    # Calculate how often the full, raw baseline triggered its own threshold
    violations_baseline = len(df_baseline[df_baseline["packet_count"] > threshold])
    fpr_baseline = (violations_baseline / len(df_baseline)) * 100

    # Calculate how often the structured test traffic triggers the baseline threshold
    violations_test = len(df_test[df_test["packet_count"] > threshold])
    fpr_test = (violations_test / len(df_test)) * 100

    print("--- IDS Simulation Results ---")
    print(f"[{args.baseline_label} Outlier Cap Set At: {cap:.0f} pkts/sec]")
    print(f"{args.baseline_label} Mean: {mean_baseline:.2f} pkts/sec")
    print(f"IDS Threshold: {threshold:.2f} pkts/sec")
    print(f"{args.baseline_label} Self-Violation Rate: {fpr_baseline:.2f}%")
    print(f"{args.test_label} False Positive Rate: {fpr_test:.2f}%")

    # 3. Visualization
    fig, ax = plt.subplots(figsize=(16, 8))

    # Plot the full, raw distributions of both datasets so reality is not hidden
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

    # Draw the rigid IDS Threshold line
    ax.axvline(
        threshold,
        color="black",
        linestyle="--",
        linewidth=3,
        label=f"IDS Threshold\n({threshold:.0f} pkts/s)",
    )

    ax.set_xlabel("Packets per Second", labelpad=20, fontweight="bold")
    ax.set_ylabel("Probability Density", labelpad=20, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    # Remove top and right borders for a cleaner aesthetic
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.05),
        ncol=3,
        framealpha=0.9,
        edgecolor="black",
    )

    plt.tight_layout()
    out_png = f"{args.outdir}/ids_degradation.png"
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    print(f"[+] Visualization saved to {out_png}")


if __name__ == "__main__":
    main()
