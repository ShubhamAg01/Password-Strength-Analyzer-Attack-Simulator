import math
import re
from typing import Dict, List, Any, Set

KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "qazwsxedcrfvtgbyhnujmikolp"
]

LEET_MAP = {
    '@': 'a', '4': 'a',
    '8': 'b',
    '3': 'e',
    '1': 'i', '!': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't', '+': 't'
}

COMMON_WEAK_WORDS = {
    "password", "admin", "welcome", "login", "secret", "master", "monkey",
    "dragon", "football", "baseball", "iloveyou", "trustno1", "letmein",
    "shadow", "sunshine", "superman", "princess", "starwars", "passcode"
}


class PasswordStrengthAnalyzer:
    @staticmethod
    def calculate_shannon_entropy(password: str) -> float:
        if not password:
            return 0.0
        
        length = len(password)
        char_counts: Dict[str, int] = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        for count in char_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return round(entropy, 2)

    @staticmethod
    def calculate_pool_entropy(password: str) -> Dict[str, Any]:
        if not password:
            return {"pool_size": 0, "entropy_bits": 0.0, "character_classes": []}

        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        pool_size = 0
        classes = []
        if has_lower:
            pool_size += 26
            classes.append("Lowercase (26)")
        if has_upper:
            pool_size += 26
            classes.append("Uppercase (26)")
        if has_digits:
            pool_size += 10
            classes.append("Digits (10)")
        if has_special:
            pool_size += 32
            classes.append("Special Symbols (32)")

        length = len(password)
        entropy_bits = length * math.log2(pool_size) if pool_size > 0 else 0.0

        return {
            "pool_size": pool_size,
            "entropy_bits": round(entropy_bits, 2),
            "character_classes": classes,
            "length": length
        }

    @staticmethod
    def detect_patterns(password: str, common_wordlist: Set[str] = None) -> Dict[str, Any]:
        patterns_found: List[str] = []
        penalties = 0.0
        pwd_lower = password.lower()

        if re.search(r'(.)\1{2,}', pwd_lower):
            patterns_found.append("Repeated characters ('aaa' or '111')")
            penalties += 8.0

        seq_nums = ["0123", "1234", "2345", "3456", "4567", "5678", "6789", "7890",
                    "0987", "9876", "8765", "7654", "6543", "5432", "4321"]
        for seq in seq_nums:
            if seq in pwd_lower:
                patterns_found.append(f"Sequential digits ('{seq}')")
                penalties += 10.0
                break

        seq_letters = ["abcd", "bcde", "cdef", "defg", "efgh", "fghi", "ghij", "hijk",
                       "ijkl", "jklm", "klmn", "lmno", "mnop", "nopq", "opqr", "pqrs",
                       "qrst", "rstu", "stuv", "tuvw", "uvwx", "vwxy", "wxyz"]
        for seq in seq_letters:
            if seq in pwd_lower:
                patterns_found.append(f"Sequential letters ('{seq}')")
                penalties += 10.0
                break

        for kb in KEYBOARD_PATTERNS:
            for i in range(len(kb) - 3):
                sub = kb[i:i + 4]
                if sub in pwd_lower or sub[::-1] in pwd_lower:
                    patterns_found.append(f"Keyboard pattern ('{sub}')")
                    penalties += 12.0
                    break

        if re.search(r'(19[5-9]\d|20[0-3]\d)', pwd_lower):
            patterns_found.append("Embedded 4-digit year")
            penalties += 6.0

        normalized_chars = [LEET_MAP.get(ch, ch) for ch in pwd_lower]
        normalized_str = "".join(normalized_chars)

        active_wordlist = COMMON_WEAK_WORDS if common_wordlist is None else common_wordlist
        found_word = None
        for word in active_wordlist:
            if word in normalized_str and len(word) >= 4:
                found_word = word
                break
        
        if found_word:
            patterns_found.append(f"Common dictionary word: '{found_word}'")
            penalties += 16.0

        return {
            "patterns": patterns_found,
            "pattern_penalty_bits": round(penalties, 2),
            "normalized_str": normalized_str
        }

    @classmethod
    def estimate_crack_times(cls, effective_entropy: float) -> Dict[str, str]:
        total_combinations = 2 ** max(1.0, effective_entropy)
        avg_guesses = total_combinations / 2.0

        rates = {
            "online_throttled": 100.0 / 3600.0,
            "online_unthrottled": 100.0,
            "offline_fast_gpu_md5": 10_000_000_000.0,
            "offline_slow_bcrypt": 10_000.0
        }

        def format_time(seconds: float) -> str:
            if seconds < 1e-4:
                return "< 0.1 ms"
            elif seconds < 1.0:
                return f"{round(seconds * 1000, 2)} ms"
            elif seconds < 60:
                return f"{round(seconds, 2)} seconds"
            elif seconds < 3600:
                return f"{round(seconds / 60, 2)} minutes"
            elif seconds < 86400:
                return f"{round(seconds / 3600, 2)} hours"
            elif seconds < 365.25 * 86400:
                return f"{round(seconds / 86400, 2)} days"
            elif seconds < 1000 * 365.25 * 86400:
                return f"{round(seconds / (365.25 * 86400), 2)} years"
            else:
                return f"{seconds / (365.25 * 86400):.2e} years"

        return {
            "online_throttled": format_time(avg_guesses / rates["online_throttled"]),
            "online_unthrottled": format_time(avg_guesses / rates["online_unthrottled"]),
            "offline_fast_gpu_md5": format_time(avg_guesses / rates["offline_fast_gpu_md5"]),
            "offline_slow_bcrypt": format_time(avg_guesses / rates["offline_slow_bcrypt"]),
            "total_search_space": f"{total_combinations:.2e}"
        }

    @classmethod
    def analyze(cls, password: str, common_wordlist: Set[str] = None) -> Dict[str, Any]:
        if not password:
            return {
                "password_length": 0,
                "score": 0,
                "rating": "Very Weak",
                "color_hex": "#ef4444",
                "shannon_entropy": 0.0,
                "pool_size": 0,
                "raw_pool_entropy": 0.0,
                "pattern_penalty": 0.0,
                "effective_entropy": 0.0,
                "character_classes": [],
                "patterns_detected": [],
                "feedback": ["Password cannot be empty."],
                "crack_times": cls.estimate_crack_times(0.0)
            }

        shannon = cls.calculate_shannon_entropy(password)
        pool_data = cls.calculate_pool_entropy(password)
        pattern_data = cls.detect_patterns(password, common_wordlist)

        raw_entropy = pool_data["entropy_bits"]
        penalty = pattern_data["pattern_penalty_bits"]
        effective_entropy = max(5.0, round(raw_entropy - penalty, 2))

        if effective_entropy < 28:
            rating = "Very Weak"
            score = min(25, int(effective_entropy))
            color = "#ef4444"
        elif effective_entropy < 36:
            rating = "Weak"
            score = 25 + int((effective_entropy - 28) / (36 - 28) * 20)
            color = "#f97316"
        elif effective_entropy < 60:
            rating = "Fair"
            score = 45 + int((effective_entropy - 36) / (60 - 36) * 25)
            color = "#eab308"
        elif effective_entropy < 80:
            rating = "Strong"
            score = 70 + int((effective_entropy - 60) / (80 - 60) * 20)
            color = "#22c55e"
        else:
            rating = "Very Strong"
            score = min(100, 90 + int((effective_entropy - 80) / 40 * 10))
            color = "#10b981"

        feedback: List[str] = []
        if len(password) < 8:
            feedback.append("Length is under 8 characters; easy to brute-force.")
        elif len(password) < 12:
            feedback.append("Extending to 12-16 characters significantly improves security.")
        
        if len(pool_data["character_classes"]) < 3:
            feedback.append("Mix lowercase, uppercase, numbers, and symbols to enlarge search space.")

        for pat in pattern_data["patterns"]:
            feedback.append(f"Pattern detected: {pat}")

        if not feedback:
            feedback.append("Strong password; resistant against dictionary and rule-based attacks.")

        crack_times = cls.estimate_crack_times(effective_entropy)

        return {
            "password_length": len(password),
            "score": score,
            "rating": rating,
            "color_hex": color,
            "shannon_entropy": shannon,
            "pool_size": pool_data["pool_size"],
            "raw_pool_entropy": raw_entropy,
            "pattern_penalty": penalty,
            "effective_entropy": effective_entropy,
            "character_classes": pool_data["character_classes"],
            "patterns_detected": pattern_data["patterns"],
            "feedback": feedback,
            "crack_times": crack_times
        }
