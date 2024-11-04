from crypteia.parsers.rapid7 import rapid7 as rp
from crypteia.parsers.tenable import tenable as tp
from crypteia.parsers.inspector import inspector as ip


def extract(vendor: str, vuln_file):
    vendor = vendor
    
    if vendor == "Inspector":
        unique_cves = ip(vuln_file)
        return unique_cves
    if vendor == "Rapid7":
        unique_cves = rp(vuln_file)
        return unique_cves
    if vendor == 'Tenable':
        unique_cves = tp(vuln_file)
        return unique_cves

if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    unique_cves = extract(app_config, user_config)
    print(unique_cves)