def detect_fast_flux(domain_ list, config: dict) -> bool:
    if len(domain_data) < config["thresholds"]["fast_flux"]["min_ip_count"]:
        return False
    ttls = [r.get("ttl", 999) for r in domain_data if r.get("ttl") is not None]
    if not ttls:
        return False
    if max(ttls) > config["thresholds"]["fast_flux"]["max_ttl_seconds"]:
        return False
    return True
