import json
import os
from typing import List, Dict, Any
from src.attack_simulator import AttackSimulator

BASE_PASSWORDS = [
    "password", "123456", "123456789", "guest", "qwerty", "12345678", "111111",
    "12345", "1234567", "dragon", "welcome", "ninja", "sunshine", "princess",
    "football", "iloveyou", "admin", "monkey", "shadow", "master", "computer",
    "security", "cyber", "winter123", "jaipur", "test1234", "hacker", "network",
    "database", "system", "cisco", "root", "oracle", "secret", "trustno1",
    "superman", "batman", "starwars", "login", "access", "passcode", "student",
    "college", "engineering", "techno", "router", "terminal", "server", "matrix",
    "phoenix", "freedom", "champion", "winter", "summer", "autumn", "spring",
    "coffee", "chocolate", "guitar", "music", "family", "orange", "apple",
    "windows", "linux", "ubuntu", "android", "iphone", "google", "facebook",
    "instagram", "twitter", "linkedin", "amazon", "netflix", "microsoft", "github",
    "python", "javascript", "developer", "programmer", "software", "hardware",
    "machine", "learning", "artificial", "intelligence", "algorithm", "crypto",
    "cipher", "sha256", "binary", "kernel", "packet", "firewall", "gateway",
    "proxy", "tunnel", "socket", "port80", "exploit", "payload", "scanner"
]


def generate_curated_wordlist(output_path: str = "wordlists/common_passwords.txt", target_count: int = 1500) -> List[str]:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    words = set(BASE_PASSWORDS)
    
    for b in list(BASE_PASSWORDS)[:40]:
        for n in ["1", "12", "123", "2024", "2025", "2026", "01", "7", "99", "!"]:
            words.add(f"{b}{n}")
            words.add(f"{b.capitalize()}{n}")
            words.add(f"{b}@{n}")

    for pin in range(1000, 1250):
        words.add(str(pin))
    for pin in [1234, 4321, 1111, 2222, 0000, 1212, 6969, 7777, 9999, 2026]:
        words.add(str(pin))

    # Pad with additional numeric PINs so the corpus hits the exact
    # advertised size of 1,500 entries.
    extra_pin = 1250
    while len(words) < target_count:
        words.add(str(extra_pin))
        extra_pin += 1

    sorted_words = sorted(words)
    with open(output_path, "w", encoding="utf-8") as f:
        for w in sorted_words:
            f.write(f"{w}\n")

    return sorted_words


def generate_test_target_hashes(output_path: str = "wordlists/test_hashes.json") -> List[Dict[str, Any]]:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    test_scenarios = [
        {
            "id": "TC-01",
            "name": "PIN",
            "plaintext": "123456",
            "category": "Numeric Sequential",
            "bcrypt_rounds": 8
        },
        {
            "id": "TC-02",
            "name": "Dictionary Word",
            "plaintext": "password",
            "category": "Dictionary Word",
            "bcrypt_rounds": 8
        },
        {
            "id": "TC-03",
            "name": "Default Admin Credential",
            "plaintext": "admin123",
            "category": "Hybrid Word+Number",
            "bcrypt_rounds": 8
        },
        {
            "id": "TC-04",
            "name": "Keyboard Walk",
            "plaintext": "qwerty",
            "category": "Spatial Pattern",
            "bcrypt_rounds": 8
        },
        {
            "id": "TC-05",
            "name": "Leet-Speak Mutated",
            "plaintext": "p@ssw0rd",
            "category": "Leet Substitution",
            "bcrypt_rounds": 8
        },
        {
            "id": "TC-06",
            "name": "Common Password",
            "plaintext": "winter123",
            "category": "Common Term",
            "bcrypt_rounds": 8
        },
        {
            "id": "TC-07",
            "name": "Complex Random String",
            "plaintext": "K#9vX$2mQ!z8",
            "category": "High Entropy Random",
            "bcrypt_rounds": 8
        }
    ]

    for tc in test_scenarios:
        pwd = tc["plaintext"]
        rounds = tc["bcrypt_rounds"]
        tc["md5_hash"] = AttackSimulator.generate_hash(pwd, "md5")
        tc["sha1_hash"] = AttackSimulator.generate_hash(pwd, "sha1")
        tc["bcrypt_hash"] = AttackSimulator.generate_hash(pwd, "bcrypt", bcrypt_rounds=rounds)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(test_scenarios, f, indent=2)

    return test_scenarios


if __name__ == "__main__":
    generate_curated_wordlist()
    generate_test_target_hashes()
