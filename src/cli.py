import sys
import os
import json
import time
from src.entropy_analyzer import PasswordStrengthAnalyzer
from src.attack_simulator import AttackSimulator


def print_banner():
    print("""
===================================================
     Password Strength & Attack Simulator
===================================================
""")


def load_wordlist(filepath: str = "wordlists/common_passwords.txt"):
    if not os.path.exists(filepath):
        from src.wordlist_generator import generate_curated_wordlist
        return generate_curated_wordlist(filepath)
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def handle_entropy_analysis(wordlist):
    print("\nPassword Evaluation")
    print("-" * 30)
    pwd = input("Enter password (or 'exit'): ").strip()
    if not pwd or pwd.lower() == 'exit':
        return

    res = PasswordStrengthAnalyzer.analyze(pwd, set(wordlist))
    print("\nResults:")
    print(f"  Length:             {res['password_length']}")
    print(f"  Rating:             {res['rating']} ({res['score']}/100)")
    print(f"  Shannon Entropy:    {res['shannon_entropy']} b/c")
    print(f"  Pool Size:          {res['pool_size']}")
    print(f"  Raw Pool Entropy:   {res['raw_pool_entropy']} bits")
    print(f"  Pattern Penalty:    -{res['pattern_penalty']} bits")
    print(f"  Effective Entropy:  {res['effective_entropy']} bits")
    
    print("\nEstimated Crack Times:")
    print(f"  Online (throttled):   {res['crack_times']['online_throttled']}")
    print(f"  Online (unthrottled): {res['crack_times']['online_unthrottled']}")
    print(f"  GPU MD5/SHA-1:        {res['crack_times']['offline_fast_gpu_md5']}")
    print(f"  bcrypt:               {res['crack_times']['offline_slow_bcrypt']}")

    if res['patterns_detected']:
        print("\nPatterns Found:")
        for p in res['patterns_detected']:
            print(f"  - {p}")

    print("\nRecommendations:")
    for f in res['feedback']:
        print(f"  - {f}")


def handle_hash_generator():
    print("\nHash Generator")
    print("-" * 30)
    pwd = input("Enter text to hash: ").strip()
    if not pwd:
        return
    
    md5_h = AttackSimulator.generate_hash(pwd, "md5")
    sha1_h = AttackSimulator.generate_hash(pwd, "sha1")
    bcrypt_h = AttackSimulator.generate_hash(pwd, "bcrypt", bcrypt_rounds=8)

    print(f"MD5:    {md5_h}")
    print(f"SHA-1:  {sha1_h}")
    print(f"bcrypt: {bcrypt_h}")


def handle_dictionary_attack(wordlist):
    print("\nDictionary Attack")
    print("-" * 30)
    print("Algorithm:")
    print("  1. MD5")
    print("  2. SHA-1")
    print("  3. bcrypt")
    choice = input("Choice (1-3): ").strip()
    algo_map = {"1": "md5", "2": "sha1", "3": "bcrypt"}
    algo = algo_map.get(choice, "md5")

    target_hash = input(f"Target {algo.upper()} hash (leave blank to hash a word): ").strip()
    if not target_hash:
        test_word = input("Word to hash and crack (default 'admin123'): ").strip() or "admin123"
        rounds = 8 if algo == 'bcrypt' else 10
        target_hash = AttackSimulator.generate_hash(test_word, algo, bcrypt_rounds=rounds)
        print(f"Target hash: {target_hash}")

    enable_rules = input("Enable rule mutations? (y/N): ").strip().lower() == 'y'
    if algo == 'bcrypt':
        active_wl = wordlist[:20] if enable_rules else wordlist[:50]
    else:
        active_wl = wordlist

    print(f"Running attack against {algo.upper()}...")
    res = AttackSimulator.run_dictionary_attack(target_hash, algo, active_wl, enable_rules=enable_rules)

    print("\nOutcome:")
    print(f"  Status:       {'Cracked' if res['cracked'] else 'Failed'}")
    if res['cracked']:
        print(f"  Password:     {res['cracked_password']}")
    print(f"  Attempts:     {res['attempts']}")
    print(f"  Time:         {res['elapsed_seconds']}s")
    print(f"  Speed:        {res['hash_rate_per_sec']:,.2f} H/s")


def handle_brute_force():
    print("\nBrute Force Attack")
    print("-" * 30)
    algo = input("Algorithm (md5 / sha1) [md5]: ").strip().lower() or "md5"
    pwd = input("Secret to crack (1-3 chars, default 'cat'): ").strip() or "cat"
    
    target_hash = AttackSimulator.generate_hash(pwd, algo)
    print(f"Target hash: {target_hash}")
    max_len = int(input("Max search length (1-3) [3]: ").strip() or "3")

    print("Searching...")
    res = AttackSimulator.run_brute_force_attack(target_hash, algo, max_length=max_len)

    print("\nOutcome:")
    print(f"  Status:       {'Cracked' if res['cracked'] else 'Failed'}")
    if res['cracked']:
        print(f"  Password:     {res['cracked_password']}")
    print(f"  Attempts:     {res['attempts']}")
    print(f"  Time:         {res['elapsed_seconds']}s")
    print(f"  Speed:        {res['hash_rate_per_sec']:,.2f} H/s")


def handle_batch_tests():
    print("\nBatch Test Suite")
    print("-" * 30)
    if not os.path.exists("wordlists/test_hashes.json"):
        from src.wordlist_generator import generate_test_target_hashes
        generate_test_target_hashes()

    with open("wordlists/test_hashes.json", "r", encoding="utf-8") as f:
        cases = json.load(f)

    print(f"{'ID':<7} | {'Password':<15} | {'Category':<22} | {'Rating':<12} | {'Bits'}")
    print("-" * 68)
    for c in cases:
        analysis = PasswordStrengthAnalyzer.analyze(c["plaintext"])
        print(f"{c['id']:<7} | {c['plaintext']:<15} | {c['category']:<22} | {analysis['rating']:<12} | {analysis['effective_entropy']}")


def run_cli():
    print_banner()
    wordlist = load_wordlist()

    while True:
        print("\nMenu:")
        print("  1. Password strength and entropy analysis")
        print("  2. Generate hashes (MD5, SHA-1, bcrypt)")
        print("  3. Dictionary attack")
        print("  4. Brute force attack")
        print("  5. Run batch test cases")
        print("  6. Launch web UI")
        print("  7. Exit")

        choice = input("\nChoice (1-7): ").strip()
        if choice == '1':
            handle_entropy_analysis(wordlist)
        elif choice == '2':
            handle_hash_generator()
        elif choice == '3':
            handle_dictionary_attack(wordlist)
        elif choice == '4':
            handle_brute_force()
        elif choice == '5':
            handle_batch_tests()
        elif choice == '6':
            from src.web_app import run_web_server
            run_web_server()
            break
        elif choice == '7':
            break


if __name__ == "__main__":
    run_cli()
