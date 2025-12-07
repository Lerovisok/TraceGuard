import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    probabilities = [count / len(s) for count in counter.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
    return entropy

def vowel_ratio(domain: str) -> float:
    vowels = "aeiou"
    clean = ''.join(c for c in domain.lower() if c.isalpha())
    if not clean:
        return 0.0
    vowel_count = sum(1 for c in clean if c in vowels)
    return vowel_count / len(clean)
