import pandas as pd

from crypteia import * 



if __name__ == "__main__":

    app_config, user_config = config.bootstrap()
    
    #* Download required files for operations
    kev.download(app_config, user_config)
    # epss.download(app_config, user_config)
    # ghdb.download(app_config, user_config)
    # nomi.download(app_config, user_config)

    unique_cves_tuple = vuln_report.extract(app_config, user_config)
    nvd_data = nvd.nvd_controller(app_config, user_config ,unique_cves_tuple)

    kev_dataframe = kev.create_dataframe(app_config)
    kev_dataframe = kev_dataframe["data"]

    
    unique_cves = vuln_report.extract(app_config, user_config)
    
    # print(unique_cves)
    
    # unique_cves = ("CVE-2016-3427", "CVE-2020-3433", "CVE-2021-30632")
    s = pd.Series(unique_cves)
    cve_dataframe = pd.DataFrame(s, columns=['cveID'])
    
    print(type(cve_dataframe))
    print(type(kev_dataframe))
    
    result_dataframe = pd.merge(cve_dataframe, kev_dataframe, on="cveID", how="inner")
    print(result_dataframe)
    
    
    
