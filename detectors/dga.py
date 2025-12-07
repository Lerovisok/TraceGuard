from utils.features import vowel_ratio

def detect_dga(domain: str, config: dict) -> bool:
    if len(domain) < config["thresholds"]["dga"]["min_domain_length"]:
        return False
    vr = vowel_ratio(domain)
    if vr > config["thresholds"]["dga"]["max_vowel_ratio"]:
        return False
    # Add more lexical checks if needed
    return True
