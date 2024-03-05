from cve_parse import *

if __name__ == "__main__":

    app_config, user_config = config.bootstrap()
    
    # searchsploit_data = searchsploit.load_dataframe(app_config)
    
    # print(searchsploit_data["data"])
    
    unique_cves = ('CVE-2016-2183', 'CVE-2023-23375', 'CVE-2023-28304', 'CVE-2020-11022', 'CVE-2020-11023', 'CVE-2022-31777', 'CVE-1999-0113')
    
    cve_list = list(unique_cves)
    
    print(cve_list)
    cve_list.sort()
    print(cve_list)
    
    