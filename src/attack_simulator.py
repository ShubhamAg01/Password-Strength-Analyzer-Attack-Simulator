import hashlib
import time
import itertools
import string
from typing import Dict, List, Any, Optional, Iterator
import bcrypt


class AttackSimulator:
    @staticmethod
    def generate_hash(plaintext: str, algorithm: str, bcrypt_rounds: int = 10) -> str:
        algo = algorithm.lower().strip()
        data = plaintext.encode('utf-8')
        
        if algo == 'md5':
            return hashlib.md5(data).hexdigest()
        elif algo == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif algo == 'bcrypt':
            salt = bcrypt.gensalt(rounds=bcrypt_rounds)
            return bcrypt.hashpw(data, salt).decode('utf-8')
        else:
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: md5, sha1, bcrypt.")

    @staticmethod
    def verify_hash(candidate: str, target_hash: str, algorithm: str) -> bool:
        algo = algorithm.lower().strip()
        cand_bytes = candidate.encode('utf-8')

        if algo == 'md5':
            return hashlib.md5(cand_bytes).hexdigest().lower() == target_hash.lower()
        elif algo == 'sha1':
            return hashlib.sha1(cand_bytes).hexdigest().lower() == target_hash.lower()
        elif algo == 'bcrypt':
            try:
                target_bytes = target_hash.encode('utf-8')
                return bcrypt.checkpw(cand_bytes, target_bytes)
            except Exception:
                return False
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    @staticmethod
    def mutate_word(word: str) -> List[str]:
        mutations = set()
        mutations.add(word)
        mutations.add(word.capitalize())
        mutations.add(word.upper())
        mutations.add(word.lower())

        suffixes = ["1", "12", "123", "1234", "!", "@", "#", "2024", "2025", "2026", "01"]
        for base in [word, word.capitalize()]:
            for suf in suffixes:
                mutations.add(f"{base}{suf}")
                mutations.add(f"{base}@{suf}")

        # Leet-speak engine: single AND combined multi-position substitutions
        # (e.g. 'password' -> 'p@ssw0rd' requires mutating 'a' AND 'o' together,
        # exactly like cumulative hashcat rules). Variants are capped to keep
        # the candidate space bounded for slow algorithms such as bcrypt.
        leet_chars = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'],
            'o': ['0'], 's': ['$', '5'], 't': ['7']
        }
        chars = list(word.lower())
        options = [[ch] + leet_chars[ch] if ch in leet_chars else [ch] for ch in chars]

        MAX_LEET_VARIANTS = 64
        leet_variants = []
        for combo in itertools.product(*options):
            if len(leet_variants) >= MAX_LEET_VARIANTS:
                break
            variant = "".join(combo)
            if variant != word:
                leet_variants.append(variant)

        for variant in leet_variants:
            mutations.add(variant)
            mutations.add(variant.capitalize())

        return list(mutations)

    @classmethod
    def run_dictionary_attack(
        cls,
        target_hash: str,
        algorithm: str,
        wordlist: List[str],
        enable_rules: bool = False,
        max_attempts: Optional[int] = None
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()
        attempts = 0
        cracked = False
        cracked_password = None

        def candidate_generator() -> Iterator[str]:
            for raw_word in wordlist:
                cleaned = raw_word.strip()
                if not cleaned:
                    continue
                if enable_rules:
                    for mutated in cls.mutate_word(cleaned):
                        yield mutated
                else:
                    yield cleaned

        for candidate in candidate_generator():
            attempts += 1
            if cls.verify_hash(candidate, target_hash, algorithm):
                cracked = True
                cracked_password = candidate
                break
            
            if max_attempts and attempts >= max_attempts:
                break

        elapsed = max(time.perf_counter() - start_time, 1e-9)
        hash_rate = attempts / elapsed

        return {
            "cracked": cracked,
            "cracked_password": cracked_password,
            "algorithm": algorithm.lower(),
            "target_hash": target_hash,
            "attempts": attempts,
            "elapsed_seconds": round(elapsed, 6),
            "hash_rate_per_sec": round(hash_rate, 2),
            "attack_type": "Hybrid Rule-Based Attack" if enable_rules else "Dictionary Attack"
        }

    @classmethod
    def run_brute_force_attack(
        cls,
        target_hash: str,
        algorithm: str,
        max_length: int = 4,
        charset: str = string.ascii_lowercase + string.digits,
        max_attempts: int = 100_000
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()
        attempts = 0
        cracked = False
        cracked_password = None

        for length in range(1, max_length + 1):
            if cracked or attempts >= max_attempts:
                break
            for combo in itertools.product(charset, repeat=length):
                candidate = "".join(combo)
                attempts += 1
                if cls.verify_hash(candidate, target_hash, algorithm):
                    cracked = True
                    cracked_password = candidate
                    break
                if attempts >= max_attempts:
                    break

        elapsed = max(time.perf_counter() - start_time, 1e-9)
        hash_rate = attempts / elapsed

        return {
            "cracked": cracked,
            "cracked_password": cracked_password,
            "algorithm": algorithm.lower(),
            "target_hash": target_hash,
            "attempts": attempts,
            "elapsed_seconds": round(elapsed, 6),
            "hash_rate_per_sec": round(hash_rate, 2),
            "attack_type": f"Brute Force (max len={max_length}, charset size={len(charset)})"
        }

    @classmethod
    def run_comparative_benchmark(
        cls,
        test_password: str,
        wordlist_sample: List[str],
        sample_size: int = 50
    ) -> Dict[str, Any]:
        sample = wordlist_sample[:sample_size]
        if test_password not in sample:
            sample.append(test_password)

        results: Dict[str, Any] = {}

        md5_hash = cls.generate_hash(test_password, 'md5')
        md5_res = cls.run_dictionary_attack(md5_hash, 'md5', sample)
        results["md5"] = {
            "hash": md5_hash,
            "time_sec": md5_res["elapsed_seconds"],
            "hash_rate": md5_res["hash_rate_per_sec"],
            "attempts": md5_res["attempts"],
            "cracked": md5_res["cracked"]
        }

        sha1_hash = cls.generate_hash(test_password, 'sha1')
        sha1_res = cls.run_dictionary_attack(sha1_hash, 'sha1', sample)
        results["sha1"] = {
            "hash": sha1_hash,
            "time_sec": sha1_res["elapsed_seconds"],
            "hash_rate": sha1_res["hash_rate_per_sec"],
            "attempts": sha1_res["attempts"],
            "cracked": sha1_res["cracked"]
        }

        bcrypt_sample = sample[:10]
        if test_password not in bcrypt_sample:
            bcrypt_sample.append(test_password)

        bcrypt_hash_cost8 = cls.generate_hash(test_password, 'bcrypt', bcrypt_rounds=8)
        bcrypt_res_cost8 = cls.run_dictionary_attack(bcrypt_hash_cost8, 'bcrypt', bcrypt_sample)
        results["bcrypt_cost8"] = {
            "hash": bcrypt_hash_cost8,
            "time_sec": bcrypt_res_cost8["elapsed_seconds"],
            "hash_rate": bcrypt_res_cost8["hash_rate_per_sec"],
            "attempts": bcrypt_res_cost8["attempts"],
            "cracked": bcrypt_res_cost8["cracked"]
        }

        bcrypt_hash_cost10 = cls.generate_hash(test_password, 'bcrypt', bcrypt_rounds=10)
        bcrypt_res_cost10 = cls.run_dictionary_attack(bcrypt_hash_cost10, 'bcrypt', bcrypt_sample[:5])
        results["bcrypt_cost10"] = {
            "hash": bcrypt_hash_cost10,
            "time_sec": bcrypt_res_cost10["elapsed_seconds"],
            "hash_rate": bcrypt_res_cost10["hash_rate_per_sec"],
            "attempts": bcrypt_res_cost10["attempts"],
            "cracked": bcrypt_res_cost10["cracked"]
        }

        return {
            "test_password": test_password,
            "benchmarks": results
        }
