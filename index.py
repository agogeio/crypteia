import os
import pandas as pd
import time

from cve_parse import config
from cve_parse import download
from cve_parse import exploitdb
from cve_parse import kev
from cve_parse import nvd
from cve_parse import vuln_report
from cve_parse import write_report

NVD_API_KEY = os.environ.get("NVD_API_KEY")


if __name__ == "__main__":
    start = time.time()
    
    app_config, user_config = config.bootstrap()
    
    #* Download required files for operations
    download.epss(app_config, user_config)
    download.exploitdb(app_config, user_config)
    download.kev(app_config, user_config)
    download.nvd(app_config, user_config)
    
    #* Extract required data from exploit DB
    exploitdb.extract(app_config)
    #* Extract unique CVEs from provided vulnerability report
    unique_cves_tuple = vuln_report.extract(app_config, user_config)
    #* Set NVD sleep timer if using the API if an API key is present
    nvd_api_sleep_timer = nvd.calculate_run_time(unique_cves_tuple)
    
    #* Load data from the NVD API, performance is limited by speed of the API
    nvd_data = nvd.nvd_controller(app_config, user_config ,unique_cves_tuple)
    
    # print(nvd_data)
    
    
    kev_dataframe = kev.create_dataframe(app_config)
    kev_report = kev.build_report(kev_dataframe, nvd_data)
    
    #* In the write report file there is also an option to write a csv file
    excel_file_path = write_report.excel(user_config, kev_report)

    print(f"\nTotal Processing Time: {round((time.time() - start)/60, 2)} minutes")



