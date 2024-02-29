import time

from cve_parse import *

if __name__ == "__main__":
    start = time.time()
    app_config, user_config = config.bootstrap()
    
    #* Download required files for operations
    kev.download(app_config, user_config)
    epss.download(app_config, user_config)
    ghdb.download(app_config, user_config)
    nomi.download(app_config, user_config)
    
    #! I need to update the NVD dataset to use utils
    nvd.download(app_config, user_config)
    
    print(f"\nTotal Download Time: {round((time.time() - start)/60, 2)} minutes")
    
    #* Extract required data from exploit DB
    ghdb.extract(app_config)
    #* Extract unique CVEs from provided vulnerability report
    unique_cves_tuple = vuln_report.extract(app_config, user_config)
    
    #* Set NVD sleep timer if using the API if an API key is present
    nvd_api_sleep_timer = nvd.calculate_run_time(unique_cves_tuple)
    #* Load data from the NVD API, performance is limited by speed of the API
    nvd_data = nvd.nvd_controller(app_config, user_config ,unique_cves_tuple)
    #* Capture the returned KEV Dataframe
    kev_dataframe = kev.create_dataframe(app_config)
    kev_dataframe = kev_dataframe["data"]
    #* Update the vulnerability report with KEV data
    kev_report = kev.enrich_with_kev(kev_dataframe, nvd_data)
    #* In the write report file there is also an option to write a csv file
    exploitdb_response = ghdb.create_dataframe(app_config)
    exploitdb_df = exploitdb_response["data"]
    
    print(unique_cves_tuple)
    
    # exploitdb.enrich_with_exploitdb(exploitdb_df, unique_cves_tuple)
    
    
    
    
    # excel_file_path = write_report.excel(user_config, kev_report)

    print(f"\nTotal Processing Time: {round((time.time() - start)/60, 2)} minutes")
    