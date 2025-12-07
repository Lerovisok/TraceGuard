def detect_tls_c2(record: dict, config: dict) -> bool:
    sni = record.get("server_name", "")
    issuer = record.get("issuer", "")
    thresholds = config["thresholds"]["tls_c2"]
    
    if not sni or not issuer:
        return False
        
    if thresholds["letscrypt_issuer"].lower() in issuer.lower():
        for pattern in thresholds["suspicious_snis"]:
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if sni.endswith(suffix):
                    return True
    return False
