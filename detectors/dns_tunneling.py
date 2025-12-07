from utils.features import shannon_entropy

def detect_dns_tunneling(record: dict, config: dict) -> bool:
    query = record.get("query", "")
    qtype = record.get("qtype_name", "")
    length = len(query)
    entropy = shannon_entropy(query)
    thresholds = config["thresholds"]["dns_tunneling"]
    
    if qtype not in thresholds["suspicious_record_types"]:
        return False
    if length < thresholds["min_subdomain_length"]:
        return False
    if entropy < thresholds["min_entropy"]:
        return False
    return True
