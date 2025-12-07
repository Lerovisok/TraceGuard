def detect_cloud_abuse(domain: str) -> bool:
    cloud_domains = [
        ".github.io",
        ".firebaseio.com",
        ".azurewebsites.net",
        ".cloudflareworkers.com",
        ".pages.dev"
    ]
    for cd in cloud_domains:
        if domain.endswith(cd):
            return True
    return False
