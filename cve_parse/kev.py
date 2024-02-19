import json
import sys

import pandas as pd

from cve_parse import utils


THREAT_INTEL_TYPE = 'CISA_KEV'

def build_report(KEV_df: pd.DataFrame, cve_data: list) -> list:  
    
    print("\n***** Enhancing report data with CISA KEV data *****\n")
    
    cves = cve_data
    for cve in cves:
        result = KEV_df.loc[KEV_df["cveID"] == cve[0]]
        if len(result.values) == 0:
            cve.append("Not in KEV")
            cve.append("Not in KEV")
        else:
            ransomwareUse = result["knownRansomwareCampaignUse"].values
            cve.append("In KEV")
            cve.append(ransomwareUse[0])
    
    print("KEV data processing complete")        
    
    return cves


def create_dataframe(app_config: dict):
    """ Returns the KEV dataset as a pd.Dataframe """
    
    print("\n***** Using local CISA KEV file to load into DataFrame *****\n")
    
    CISA_KEV_DIR = app_config["CISA_KEV_DIR"]
    CISA_KEV_FILE = app_config["CISA_KEV_FILE"]
    CISA_KEV_PATH = CISA_KEV_DIR+CISA_KEV_FILE
    
    try:
        with open(CISA_KEV_PATH) as KEV_file:
            KEV_data = KEV_file.read()
    except Exception as e:
        sys.exit(f'Error loading KEV File: {e}')
    else:
        KEV_json = json.loads(KEV_data)
        KEV_df =  pd.DataFrame.from_dict(KEV_json["vulnerabilities"])
        print(f"Loaded the following file into DataFrame with success: {CISA_KEV_PATH}")
        
    return KEV_df

#! Need to create the KEV update controller
def download(app_config: dict, user_config: dict):
    """ Downloads the KEV JSON file """
    
    print("\n***** Beginning processing of CISA KEV files *****\n")
    
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    CISA_KEV_DATA_AUTO_UPDATE = user_config["CISA_KEV_DATA_AUTO_UPDATE"]
    
    CISA_KEV_DOWNLOAD_URL = app_config["download_URLs"]["CISA_KEV_DOWNLOAD_URL"]
    CISA_KEV_DIR = app_config["CISA_KEV_DIR"]
    CISA_KEV_FILE = app_config["CISA_KEV_FILE"]
    
    CISA_KEV_PATH = CISA_KEV_DIR+CISA_KEV_FILE
    
    #* Checks if the directory exists and will try and create it
    response = utils.directory_manager(CISA_KEV_DIR)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager error: {response["error"]}")
    elif "error" not in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager message: {response["message"]}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")
    
    #* Checks file age and config settings to see if files should be downloaded
    response = utils.file_manager(AUTO_DOWNLOAD_ALL, CISA_KEV_DATA_AUTO_UPDATE, CISA_KEV_PATH)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} file_manager error: {response["error"]}")
    elif "error" not in response.keys():
        if response['action'] == 'download':
            response = utils.file_download(CISA_KEV_DOWNLOAD_URL, CISA_KEV_PATH)
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
        elif response['action'] == 'none':
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")











if __name__ == "__main__":
    import config
    
    nvd_data = [['CVE-2016-2183', 'Modified', 7.5, 'HIGH', 'NETWORK', 'LOW'], 
                ['CVE-2023-23375', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
                ['CVE-2023-28304', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
                ['CVE-2022-31777', 'Analyzed', 5.4, 'MEDIUM', 'NETWORK', 'LOW'], 
                ['CVE-2023-4128', 'Rejected', 'None', 'None', 'None', 'None'], 
                ['CVE-2015-2808', 'Modified', 5.0, 'None', 'NETWORK', 'LOW']]
    
    app_config, user_config = config.bootstrap()
    download(app_config, user_config)
    kev_df = create_dataframe(app_config)
    report = build_report(kev_df, nvd_data)
    
    print(f'KEV Report:\n{report}')