import os
import time
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from src.entropy_analyzer import PasswordStrengthAnalyzer
from src.attack_simulator import AttackSimulator


def generate_lab_topology_figure(output_dir: str = "results_and_graphs"):
    """Draws Fig. 3.2: the isolated lab topology (loopback-only sandbox).

    Kept separate from the timing suite so the figure can be regenerated
    without re-running the (slow) bcrypt benchmarks.
    """
    os.makedirs(output_dir, exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 4.6))
    ax.axis('off')
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    def box(text, x, y, w, h, bg, border, fontsize=9.0):
        ax.add_patch(plt.Rectangle((x, y), w, h, facecolor=bg, edgecolor=border,
                                   linewidth=2, zorder=2))
        ax.text(x + w / 2, y + h / 2, text, ha='center', va='center',
                fontsize=fontsize, fontweight='bold', color='#111827', zorder=3)

    # ---- Host workstation (dashed boundary) ------------------------------
    ax.add_patch(plt.Rectangle((0.03, 0.07), 0.55, 0.83, facecolor='#f8fafc',
                               edgecolor='#334155', linewidth=2, linestyle='--', zorder=1))
    ax.text(0.305, 0.925, 'HOST WORKSTATION  (own machine)', ha='center', va='center',
            fontsize=9, fontweight='bold', color='#334155')

    box("Python 3.13 Workbench\n\nEntropy Analyzer\nAttack Simulator\nBenchmark Suite\n\n"
        "Synthetic wordlists\nand test hashes",
        0.05, 0.14, 0.222, 0.62, '#dbeafe', '#1d4ed8', 8.3)

    box("Local browser\n127.0.0.1:5050",
        0.335, 0.64, 0.215, 0.18, '#dcfce7', '#16a34a', 8.6)

    box("Loopback interface\n127.0.0.1:5050\n(no external socket)",
        0.335, 0.14, 0.215, 0.27, '#fef3c7', '#d97706', 8.3)

    # Workbench -> loopback (local request)
    ax.annotate('', xy=(0.333, 0.28), xytext=(0.274, 0.28),
                arrowprops=dict(facecolor='#374151', edgecolor='#374151',
                                width=1.4, headwidth=8), zorder=4)
    # Browser <-> loopback (HTTP on localhost)
    ax.annotate('', xy=(0.4425, 0.63), xytext=(0.4425, 0.42),
                arrowprops=dict(facecolor='#374151', edgecolor='#374151',
                                width=1.4, headwidth=8), zorder=4)
    ax.annotate('', xy=(0.4425, 0.42), xytext=(0.4425, 0.63),
                arrowprops=dict(facecolor='#374151', edgecolor='#374151',
                                width=1.4, headwidth=8), zorder=4)
    ax.text(0.455, 0.525, 'HTTP\nloopback only', fontsize=7.6, ha='left',
            va='center', color='#374151')

    # ---- External network: present but unreachable -----------------------
    ax.add_patch(plt.Rectangle((0.72, 0.38), 0.24, 0.26, facecolor='#fee2e2',
                               edgecolor='#dc2626', linewidth=2, zorder=2))
    ax.plot([0.72, 0.96], [0.38, 0.64], color='#dc2626', linewidth=2.5, zorder=3)
    ax.plot([0.72, 0.96], [0.64, 0.38], color='#dc2626', linewidth=2.5, zorder=3)
    ax.text(0.84, 0.51, 'College LAN\nand public Internet', ha='center', va='center',
            fontsize=8.8, fontweight='bold', color='#7f1d1d', zorder=4,
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#fee2e2', edgecolor='none'))
    ax.text(0.84, 0.31, 'NOT CONTACTED', ha='center', va='center',
            fontsize=8.5, fontweight='bold', color='#b91c1c')

    ax.annotate('', xy=(0.715, 0.51), xytext=(0.585, 0.51),
                arrowprops=dict(facecolor='#9ca3af', edgecolor='#9ca3af',
                                width=1.3, headwidth=7, linestyle='dashed'), zorder=4)
    ax.text(0.65, 0.545, 'no route', fontsize=7.4, ha='center', va='bottom',
            color='#6b7280')

    # No in-image title: the numbered caption is supplied by the report.
    fig_path = os.path.join(output_dir, "fig_3_2_lab_setup.png")
    plt.savefig(fig_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    return fig_path


def plot_architecture_figure(output_dir: str = "results_and_graphs"):
    """Draws Fig. 3.1: high-level system architecture and data pipeline."""
    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.axis('off')

    boxes = [
        ("Input Password\nor Target Hash", 0.05, 0.55, 0.18, 0.25, '#dbeafe', '#1d4ed8'),
        ("Module 1:\nStrength Analyzer\n- Shannon Entropy\n- Pool Entropy\n- Pattern Detection\n- Crack Time Estimation", 0.30, 0.55, 0.32, 0.35, '#fef3c7', '#d97706'),
        ("Module 2:\nAttack Simulator\n- Wordlist Loader\n- Rule Mutations\n- MD5 / SHA-1 Engine\n- bcrypt Engine", 0.30, 0.08, 0.32, 0.35, '#fee2e2', '#dc2626'),
        ("Presentation:\n- Web Dashboard\n- Terminal CLI\n- Benchmarks", 0.70, 0.30, 0.25, 0.35, '#dcfce7', '#16a34a')
    ]

    for text, px, py, pw, ph, bg, border in boxes:
        ax.add_patch(plt.Rectangle((px, py), pw, ph, facecolor=bg, edgecolor=border,
                                   linewidth=2, transform=ax.transAxes, zorder=2))
        ax.text(px + pw/2, py + ph/2, text, ha='center', va='center',
                transform=ax.transAxes, fontsize=9.5, fontweight='bold',
                color='#111827', zorder=3)

    arrows = [
        ((0.23, 0.68), (0.30, 0.68)),
        ((0.23, 0.60), (0.30, 0.25)),
        ((0.62, 0.72), (0.70, 0.55)),
        ((0.62, 0.25), (0.70, 0.40)),
    ]
    for start, end in arrows:
        ax.annotate('', xy=end, xytext=start, xycoords='axes fraction',
                    textcoords='axes fraction',
                    arrowprops=dict(facecolor='#374151', edgecolor='#374151',
                                    width=1.5, headwidth=8), zorder=4)

    # No in-image title: the numbered caption is supplied by the report.
    fig_path = os.path.join(output_dir, "fig_3_1_system_architecture.png")
    plt.savefig(fig_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    return fig_path


def plot_throughput_figure(benchmark_data, output_dir: str = "results_and_graphs"):
    """Fig. 5.2: hash throughput comparison on a logarithmic scale."""
    algos = list(benchmark_data.keys())
    rates = [benchmark_data[k]["hash_rate"] for k in algos]
    colors = ['#ef4444', '#f97316', '#3b82f6', '#1d4ed8', '#1e3a8a']

    plt.figure(figsize=(9, 5))
    bars = plt.bar(algos, rates, color=colors, edgecolor='black', linewidth=1.2, width=0.55)
    plt.yscale('log')
    plt.ylabel('Hash Rate (Evaluations / Second)', fontsize=11, fontweight='bold')
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    for bar, rate in zip(bars, rates):
        plt.text(bar.get_x() + bar.get_width()/2.0, bar.get_height() * 1.3,
                 f"{rate:,.0f} H/s", ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.ylim(1, max(rates) * 15)
    plt.tight_layout()
    fig_path = os.path.join(output_dir, "fig_5_2_hash_rate_comparison.png")
    plt.savefig(fig_path, dpi=300)
    plt.close()
    return fig_path


def plot_crack_time_figure(benchmark_data, output_dir: str = "results_and_graphs"):
    """Fig. 5.3: time required to test 10,000 dictionary candidates."""
    algos = list(benchmark_data.keys())
    rates = [benchmark_data[k]["hash_rate"] for k in algos]
    time_10k = [10_000.0 / rate for rate in rates]

    plt.figure(figsize=(9, 5))
    bars = plt.bar(algos, time_10k,
                   color=['#ef4444', '#f97316', '#10b981', '#059669', '#047857'],
                   edgecolor='black', linewidth=1.2, width=0.55)
    plt.yscale('log')
    plt.ylabel('Attack Duration for 10,000 Words (Seconds)', fontsize=11, fontweight='bold')
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    for bar, t_val in zip(bars, time_10k):
        if t_val < 0.01:
            lbl = f"{t_val*1000:.1f} ms"
        elif t_val < 60:
            lbl = f"{t_val:.1f} s"
        elif t_val < 3600:
            lbl = f"{t_val/60:.1f} min"
        else:
            lbl = f"{t_val/3600:.1f} hrs"
        plt.text(bar.get_x() + bar.get_width()/2.0, bar.get_height() * 1.3,
                 lbl, ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.ylim(min(time_10k) * 0.3, max(time_10k) * 15)
    plt.tight_layout()
    fig_path = os.path.join(output_dir, "fig_5_3_crack_time_comparison.png")
    plt.savefig(fig_path, dpi=300)
    plt.close()
    return fig_path


def plot_entropy_figure(output_dir: str = "results_and_graphs",
                        test_hashes_path: str = "wordlists/test_hashes.json"):
    """Fig. 5.1: raw versus effective entropy for the TC-01..TC-07 scenarios."""
    with open(test_hashes_path, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    labels, raw_entropies, eff_entropies = [], [], []
    for tc in test_cases:
        analysis = PasswordStrengthAnalyzer.analyze(tc["plaintext"])
        labels.append(f"{tc['id']}: {tc['plaintext']}")
        raw_entropies.append(analysis["raw_pool_entropy"])
        eff_entropies.append(analysis["effective_entropy"])

    x = np.arange(len(labels))
    width = 0.35

    plt.figure(figsize=(10, 5.5))
    plt.bar(x - width/2, raw_entropies, width, label='Raw Pool Entropy',
            color='#93c5fd', edgecolor='navy')
    plt.bar(x + width/2, eff_entropies, width,
            label='Effective Entropy (After Penalties)', color='#3b82f6', edgecolor='black')

    plt.axhline(y=28, color='#ef4444', linestyle='--', linewidth=1.2,
                label='Weak Threshold (28 bits)')
    plt.axhline(y=60, color='#10b981', linestyle='--', linewidth=1.2,
                label='Strong Threshold (60 bits)')

    plt.xlabel('Test Password Scenarios', fontsize=11, fontweight='bold')
    plt.ylabel('Entropy (Bits)', fontsize=11, fontweight='bold')
    plt.xticks(x, labels, rotation=25, ha='right', fontsize=9)
    plt.legend(loc='upper left', fontsize=9)
    plt.grid(axis='y', linestyle=':', alpha=0.6)
    plt.tight_layout()

    fig_path = os.path.join(output_dir, "fig_5_1_entropy_comparison.png")
    plt.savefig(fig_path, dpi=300)
    plt.close()
    return fig_path


def generate_all_figures(output_dir: str = "results_and_graphs"):
    """Redraws every report figure from the saved metrics (no re-timing).

    Benchmarks take a couple of minutes because of bcrypt; plotting from
    benchmark_metrics.json keeps figure-only changes fast and keeps the
    charts consistent with the numbers already recorded in Table 5.2.
    """
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "benchmark_metrics.json"), "r", encoding="utf-8") as f:
        benchmark_data = json.load(f)

    paths = [
        plot_entropy_figure(output_dir),
        plot_throughput_figure(benchmark_data, output_dir),
        plot_crack_time_figure(benchmark_data, output_dir),
        plot_architecture_figure(output_dir),
        generate_lab_topology_figure(output_dir),
    ]
    return paths


def run_and_save_all_benchmarks(output_dir: str = "results_and_graphs"):
    os.makedirs(output_dir, exist_ok=True)

    sample_text = "benchmark_test_string_2026"
    iterations_fast = 50_000
    iterations_bcrypt8 = 20
    iterations_bcrypt10 = 10
    iterations_bcrypt12 = 4

    t0 = time.perf_counter()
    for _ in range(iterations_fast):
        AttackSimulator.generate_hash(sample_text, "md5")
    t_md5 = time.perf_counter() - t0
    rate_md5 = iterations_fast / t_md5

    t0 = time.perf_counter()
    for _ in range(iterations_fast):
        AttackSimulator.generate_hash(sample_text, "sha1")
    t_sha1 = time.perf_counter() - t0
    rate_sha1 = iterations_fast / t_sha1

    t0 = time.perf_counter()
    for _ in range(iterations_bcrypt8):
        AttackSimulator.generate_hash(sample_text, "bcrypt", bcrypt_rounds=8)
    t_bc8 = time.perf_counter() - t0
    rate_bc8 = iterations_bcrypt8 / t_bc8

    t0 = time.perf_counter()
    for _ in range(iterations_bcrypt10):
        AttackSimulator.generate_hash(sample_text, "bcrypt", bcrypt_rounds=10)
    t_bc10 = time.perf_counter() - t0
    rate_bc10 = iterations_bcrypt10 / t_bc10

    t0 = time.perf_counter()
    for _ in range(iterations_bcrypt12):
        AttackSimulator.generate_hash(sample_text, "bcrypt", bcrypt_rounds=12)
    t_bc12 = time.perf_counter() - t0
    rate_bc12 = iterations_bcrypt12 / t_bc12

    benchmark_data = {
        "MD5": {"hash_rate": rate_md5, "time_per_1000_candidates_sec": 1000.0 / rate_md5},
        "SHA-1": {"hash_rate": rate_sha1, "time_per_1000_candidates_sec": 1000.0 / rate_sha1},
        "bcrypt (Cost 8)": {"hash_rate": rate_bc8, "time_per_1000_candidates_sec": 1000.0 / rate_bc8},
        "bcrypt (Cost 10)": {"hash_rate": rate_bc10, "time_per_1000_candidates_sec": 1000.0 / rate_bc10},
        "bcrypt (Cost 12)": {"hash_rate": rate_bc12, "time_per_1000_candidates_sec": 1000.0 / rate_bc12},
    }

    with open(os.path.join(output_dir, "benchmark_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2)

    generate_all_figures(output_dir)
    return benchmark_data


if __name__ == "__main__":
    run_and_save_all_benchmarks()
