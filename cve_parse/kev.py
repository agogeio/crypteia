import json
import sys

import pandas as pd

from cve_parse import utils

THREAT_INTEL_TYPE = 'CISA_KEV'

STATUS_ERROR = 400
STATUS_TERMINATE = 500
STATUS_OK = 200

def create_dataframe(app_config: dict) -> dict:
    """
    Accepts data from the application configuration and reads 
    the CISA_KEV_DIR and CISA_KEV_FILE values. The KEV file in JSON format
    is read and is loaded into a Pandas DataFrame for processing.

    Args:
        app_config (dict): Required the application configuration object

    Returns:
        dict: with keys: data, error (if present), message, report_columns, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    CISA_KEV_DIR = app_config["CISA_KEV_DIR"]
    CISA_KEV_FILE = app_config["CISA_KEV_FILE"]
    CISA_KEV_PATH = CISA_KEV_DIR+CISA_KEV_FILE
    
    try:
        with open(CISA_KEV_PATH) as kev_json_file:
            kev_file_object = kev_json_file.read()
    except Exception as e:
        sys.exit(f'Error loading KEV File: {e}')
    else:
        kev_json_data = json.loads(kev_file_object)
        kev_dataframe =  pd.DataFrame.from_dict(kev_json_data["vulnerabilities"])
        
        message = f"Loaded {CISA_KEV_PATH} into kev_dataframe"
        response = {"data" : kev_dataframe, "message" : message, "status" : STATUS_OK}
        
    return response


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


def enrich_with_kev(KEV_df: pd.DataFrame, cve_data: list) -> dict:  
    """
    Accepts a Pandas Dataframe that holds CISA KEV data and a list of the CVEs to 
    be enriched. CVEs will be tagged as being in the CISA KEV database or not, and 
    if a CVE is in the CISA KEV database they will be tagged as being using in 
    ransomware campaigns or not.

    Args:
        KEV_df (pd.DataFrame): Accepts a Dataframe that consists of the CISA_KEV data
        cve_data (list): A list of CVEs to process and enrich

    Returns:
        dict: with keys: data, error (if present), message, report_columns, status (200 for ok, 400 for error, 500 for terminate)
    """
    
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

    columns = ["isKEV", "knownRansomwareCampaignUse"]
    message = f"{len(cves)} unique CVEs processed"
    response = {"data": cves, "message": message, "columns": columns, "status": STATUS_OK}
    return response


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
    report = enrich_with_kev(kev_df["data"], nvd_data)
    print(f'{report["data"]}, {report["columns"]}')