import pandas as pd
import os

def parse_zeek_dns(log_path: str):
    if not os.path.exists(log_path):
        return []
    df = pd.read_csv(log_path, sep="\t", comment="#", low_memory=False, header=None)
    # Zeek dns.log fields (minimal required)
    cols = ["ts", "uid", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name", "ttl"]
    if len(df.columns) >= 8:
        df = df.iloc[:, :8]
        df.columns = cols
        return df.to_dict(orient="records")
    return []

def parse_zeek_ssl(log_path: str):
    if not os.path.exists(log_path):
        return []
    df = pd.read_csv(log_path, sep="\t", comment="#", low_memory=False, header=None)
    cols = ["ts", "uid", "id.orig_h", "id.resp_h", "server_name", "issuer"]
    if len(df.columns) >= 6:
        df = df.iloc[:, :6]
        df.columns = cols
        return df.to_dict(orient="records")
    return []
