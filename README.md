# Password Strength Analyzer & Dictionary Attack Simulator

**Course:** Cyber Security Lab (7CS4-22), RTU Kota — Credit 2, Max Marks: 100  
**Mapped Syllabus Experiment:** **Experiment 3 – Dictionary & Brute Force Attack**  
**Student Name:** **Shubham Agarwal**  
**Roll Number:** `23ESKCS815`  
**Class / Batch:** `CS-D-G2` / B.Tech VII Semester CSE  
**Institution:** Swami Keshvanand Institute of Technology, Management & Gramothan (SKIT), Jaipur  
**Submitted To:** Vikash Dhankar, Assistant Professor, Dept. of CSE (`vikash@skit.ac.in`)  
**Submission Date:** 16 November 2026 (Monday)  

---

## 1. Project Overview & Objectives

This project is an advanced, dual-component security utility designed from first principles to evaluate credential resilience and simulate offline cryptanalytic attacks in an ethically isolated laboratory environment:

1. **Password Strength & Entropy Analyzer Module**:
   - **Shannon Information Entropy**: Evaluates character distribution and information density ($H = -\sum p_i \log_2 p_i$).
   - **Character Pool Entropy**: Computes theoretical search space ($E = L \times \log_2(R)$) across NIST SP 800-63B character pools.
   - **Heuristic Pattern Recognition**: Detects repeated characters (`aaaa`), sequential runs (`123456`, `abcdef`), spatial keyboard walks (`qwerty`, `1qaz`), 4-digit calendar years, and leet-speak substitutions (`p@ssw0rd`).
   - **Empirical Crack Time Estimations**: Projects time-to-crack across 4 threat tiers (Online Throttled, Online Unthrottled, Offline Fast GPU Cluster, and Offline Slow bcrypt).

2. **Dictionary & Brute-Force Attack Simulator Module**:
   - **Supported Cryptographic Algorithms**: **MD5** (128-bit fast digest), **SHA-1** (160-bit legacy digest), and **bcrypt** (adaptive key-stretching function).
   - **Attack Paradigms**:
     - *Pure Dictionary Attack*: Fast lookup against curated wordlists.
     - *Hybrid Rule-Based Mutation Attack*: Generates permutations via capitalization, suffix/prefix variations (`admin123!`), and leet transforms.
     - *Exhaustive Brute-Force*: Combinatorial search across configurable character masks.
   - **Cryptographic Benchmarking**: Empirically proves why fast hashes fail catastrophically and how bcrypt's salt and work factor ($2^{\text{cost}}$ iterations) defeat offline attacks.

---

## 2. Directory Structure

```
d:\Projects\CS Mini Project\
│
├── src\
│   ├── __init__.py
│   ├── entropy_analyzer.py      # Shannon/pool entropy, pattern penalties, crack time
│   ├── attack_simulator.py      # MD5, SHA-1, bcrypt verification & attack modes
│   ├── wordlist_generator.py    # Generates curated wordlist & TC-01 to TC-07 targets
│   ├── generate_benchmarks.py   # Automated timing benchmark suite & graph generator
│   ├── web_app.py               # Embedded zero-dependency HTTP server & REST API
│   └── cli.py                   # Full interactive Command-Line Interface
│
├── static\                      # Modern responsive Cyber-Security Web Dashboard
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── wordlists\
│   ├── common_passwords.txt     # Generated 1,500-entry common-password corpus
│   └── test_hashes.json         # Standardized test scenarios (TC-01 through TC-07)
│
├── results_and_graphs\          # Benchmark figures & evidence screenshots for report
│   ├── fig_3_1_system_architecture.png
│   ├── fig_3_2_lab_setup.png              # Isolated laboratory setup & network topology
│   ├── fig_5_1_entropy_comparison.png
│   ├── fig_5_2_hash_rate_comparison.png
│   ├── fig_5_3_crack_time_comparison.png
│   ├── fig_5_4_web_dashboard.png          # Web GUI screenshot (evidence of execution)
│   ├── fig_5_5_web_attack_simulator.png   # Attack simulator screenshot (cracked result)
│   ├── fig_5_6_web_test_scenarios.png     # Test scenario table screenshot
│   ├── fig_5_7_cli_console.png            # CLI console output (evidence of execution)
│   └── benchmark_metrics.json
│
├── main.py                      # Master launcher (Web GUI, CLI, Benchmarks)
├── requirements.txt             # Project dependencies (bcrypt, matplotlib, numpy)
└── README.md                    # Project documentation & execution instructions
```

---

## 3. How to Run

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Launch the Project
Run the master script to choose your preferred interface:
```bash
python main.py
```

Or run dedicated modes directly:
- **Launch Interactive Web GUI** (Recommended for Live Demo):
  ```bash
  python main.py --web
  ```
  Open your web browser at **`http://localhost:5050`**.
- **Launch Interactive Terminal CLI**:
  ```bash
  python main.py --cli
  ```
- **Regenerate Benchmark Suite & Graphs**:
  ```bash
  python main.py --benchmarks
  ```

---

## 4. Empirical Benchmark Findings (Exp 3)

Measured on single-core host CPU:

| Algorithm / Configuration | Measured Throughput (H/s) | Time to Test 1,000 Words | Time to Test 10,000 Words |
| :--- | :--- | :--- | :--- |
| **MD5** (Unsalted Fast Digest) | **~460,999 H/s** | 0.0022 seconds | **0.0217 s (21.7 ms)** |
| **SHA-1** (Unsalted Fast Digest) | **~489,452 H/s** | 0.0020 seconds | **0.0204 s (20.4 ms)** |
| **bcrypt** (Cost Factor = 8) | **30.54 H/s** | 32.74 seconds | 5.46 minutes |
| **bcrypt** (Cost Factor = 10) | **7.03 H/s** | 142.26 seconds | **23.71 minutes** |
| **bcrypt** (Cost Factor = 12) | **1.70 H/s** | 586.88 seconds | **1.63 hours** |

### **Key Cryptographic Takeaways:**
1. **Speed is the Enemy of Password Hashing**: Fast algorithms (MD5, SHA-1) designed for data integrity allow attackers to test millions of guesses per second on consumer hardware and billions on GPU rigs.
2. **Adaptive Cost Factor**: bcrypt forces $2^{\text{cost}}$ rounds of the Eksblowfish key schedule. Increasing the cost from 8 to 10 multiplies the hashing time by ~4x, allowing administrators to outpace Moore's Law.
3. **Cryptographic Salt Defense**: bcrypt attaches a 128-bit random salt to every password, forcing adversaries to attack each account serially and rendering precomputed Rainbow Tables completely ineffective.

