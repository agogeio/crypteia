import json
import os
import sys

import pandas as pd

from urllib.request import urlretrieve


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
    
    CISA_KEV_DOWNLOAD_URL = app_config["download_URLs"]["CISA_KEV_DOWNLOAD_URL"]
    CISA_KEV_DIR = app_config["CISA_KEV_DIR"]
    CISA_KEV_FILE = app_config["CISA_KEV_FILE"]
    CISA_KEV_PATH = CISA_KEV_DIR+CISA_KEV_FILE
    
    CISA_KEV_download = False
    
    if os.path.isfile(CISA_KEV_PATH):
        print(f"Existing CISA KEV file located at: {CISA_KEV_PATH}")
        if user_config["CISA_KEV_DATA_AUTO_UPDATE"] == "True":
            print("CISA KEV is configured for auto update, downloading CISA KEV update")
            CISA_KEV_download = True
        elif user_config["CISA_KEV_DATA_AUTO_UPDATE"] == "False":
            print("CISA KEV is not configured for auto update, no CISA KEV update will be downloaded.")
            print("Warning, you may be using an outdated version of the CISA KEV list")
    elif not os.path.isfile(CISA_KEV_PATH):
        print(f"No existing CISA KEV file found at location: {CISA_KEV_PATH}")
        if user_config["AUTO_DOWNLOAD_ALL"] == "True":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, CISA KEV will be downloaded")
            CISA_KEV_download = True
        elif user_config["AUTO_DOWNLOAD_ALL"] == "False":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, CISA KEV will not be downloaded")    
        else:
            sys.exit("No CISA KEV File found, error processing user config settings, terminating program")
        
    if CISA_KEV_download == True:
        try:
            if not os.path.exists(CISA_KEV_DIR):
                os.makedirs(CISA_KEV_DIR)
            urlretrieve(url=CISA_KEV_DOWNLOAD_URL, filename=CISA_KEV_PATH)
        except Exception as e:
            sys.exit(f"Failed to process CISA KEV file with error: {e}")
        else:
            print(f"Updated CISA KEV file at: {CISA_KEV_PATH}")


if __name__ == "__main__":
    import config
    
    nvd_data = [['CVE-2016-2183', 'Modified', 7.5, 'HIGH', 'NETWORK', 'LOW'], 
                ['CVE-2023-23375', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
                ['CVE-2023-28304', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
                ['CVE-2022-31777', 'Analyzed', 5.4, 'MEDIUM', 'NETWORK', 'LOW'], 
                ['CVE-2023-4128', 'Rejected', 'None', 'None', 'None', 'None'], 
                ['CVE-2015-2808', 'Modified', 5.0, 'None', 'NETWORK', 'LOW']]
    
    app_config, user_config = config.bootstrap()
    kev_df = create_dataframe(app_config)
    report = build_report(kev_df, nvd_data)
    
    print(f'KEV Report:\n{report}')