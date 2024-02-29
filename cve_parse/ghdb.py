import re
import sys

import pandas as pd

from cve_parse import utils

THREAT_INTEL_TYPE = 'GHDB'

STATUS_ERROR = 400
STATUS_TERMINATE = 500
STATUS_OK = 200

def download(app_config: dict, user_config: dict):
    """ Downloads the GHDB XML file """

    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    GHDB_DATA_AUTO_UPDATE = user_config["GHDB_DATA_AUTO_UPDATE"]

    GHDB_DOWNLOAD_URL = app_config["download_URLs"]["GHDB_DOWNLOAD_URL"]
    GHDB_DIR=app_config["GHDB_DIR"]
    GHDB_XML_FILE=app_config["GHDB_XML_FILE"]
    
    GHDB_PATH=GHDB_DIR+GHDB_XML_FILE
    
    #* Checks if the directory exists and will try and create it
    response = utils.directory_manager(GHDB_DIR)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager error: {response["error"]}")
    elif "error" not in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager message: {response["message"]}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")
    
    #* Checks file age and config settings to see if files should be downloaded
    response = utils.file_manager(AUTO_DOWNLOAD_ALL, GHDB_DATA_AUTO_UPDATE, GHDB_PATH)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} file_manager error: {response["error"]}")
    elif "error" not in response.keys():
        if response['action'] == 'download':
            response = utils.file_download(GHDB_DOWNLOAD_URL, GHDB_PATH)
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
        elif response['action'] == 'none':
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")


def create_dataframe(app_config: dict) -> dict:  
    """
    Accepts data from the application configuration and reads 
    the GHDB_DIR and GHDB_EXCEL_FILE values. The GHDB file in Excel format
    is read and is loaded into a Pandas DataFrame for processing.

    Args:
        app_config (dict): Required the application configuration object

    Returns:
        dict: with keys: data, error (if present), message, report_columns, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    GHDB_DIR = app_config["GHDB_DIR"]
    GHDB_EXCEL_FILE = app_config["GHDB_EXCEL_FILE"]
    GHDB_PATH = GHDB_DIR+GHDB_EXCEL_FILE
    
    try:
        GHDB_dataframe =  pd.read_excel(GHDB_PATH)
    except Exception as e:
        sys.exit(f'Error loading KEV File: {e}')
    else:
        message = f"Loaded {GHDB_PATH} into kev_dataframe"
        response = {"data" : GHDB_dataframe, "message" : message, "status" : STATUS_OK}

    return response


#! Working here
def enrich_with_ghdb(GHDB_df: pd.DataFrame, cve_data: tuple) -> dict:  
    """
    Accepts a Pandas Dataframe that holds GHDB data and a tuple of the CVEs to 
    be enriched. CVEs will be tagged as being in the GHDB database or not, and 
    if a CVE is in the GHDB data set they will be tagged as having an exploit or not

    Args:
        GHDB_df (pd.DataFrame): Accepts a Dataframe that consists of the CISA_KEV data
        cve_data (tuple): A tuple of CVEs to process and enrich

    Returns:
        dict: with keys: data, error (if present), message, report_columns, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    cves = cve_data
    for cve in cves:
        
        print(f"CVE {cve}")
        
        #! The CVE columns are named differently in the various datasets
        #! Keep this in mind if you run into processing errors
        result = GHDB_df.loc[GHDB_df["cve_id"] == cve[0]]
        
        print(f"Result: {result}")
        
    #     if len(result.values) == 0:
    #         cve.append("Not in ExploitDB")
    #         cve.append("Not in ExploitDB")
    #     else:
    #         ransomwareUse = result["knownRansomwareCampaignUse"].values
    #         cve.append("In KEV")
    #         cve.append(ransomwareUse[0])

    # columns = ["isKEV", "knownRansomwareCampaignUse"]
    # message = f"{len(cves)} unique CVEs processed"
    # response = {"data": cves, "message": message, "columns": columns, "status": STATUS_OK}
    # return response

            
def extract(app_config: dict):
    """ Enrich CVE data with exploit data from GHDB SearchSploit """
    
    print("\n***** Beginning data enrichment with GHDB data *****\n")
    
    searchsploit_xml_path = app_config["GHDB_DIR"]+app_config["GHDB_XML_FILE"]
    searchsploit_excel_path = app_config["GHDB_DIR"]+app_config["GHDB_EXCEL_FILE"]
    #! GHDB_EXCLUSION_WORDS = app_config["GHDB_EXCLUSION_WORDS"]
    
    try:
        print(f"Attempting to process: {searchsploit_xml_path}")    
        searchsploit_df = pd.read_xml(searchsploit_xml_path, parser="etree")
        filtered_searchsploit_df = searchsploit_df[["id","link","edb","textualDescription"]]

        #! Print out complete XML database to an Excel file
        filtered_searchsploit_df.to_excel("./data/ghdb/ghdb_total.xlsx", index=False)
        
        searchsploit_cve_with_dorks_df = filtered_searchsploit_df[filtered_searchsploit_df["textualDescription"].str.contains('CVE:')]
        searchsploit_cve_with_dorks_df = searchsploit_cve_with_dorks_df.dropna()
        
        #! for word in GHDB_EXCLUSION_WORDS:
        #     searchsploit_cve_with_dorks_df = searchsploit_cve_with_dorks_df[~searchsploit_cve_with_dorks_df["textualDescription"].str.contains(word)]

        searchsploit_cve_with_dorks_df["cve_id"] = searchsploit_cve_with_dorks_df["textualDescription"].apply(filter_cve)
        searchsploit_cve_only_df = searchsploit_cve_with_dorks_df.drop('textualDescription', axis=1)

    except Exception as e:
        sys.exit(f"Unable to process GHDB file with error: {e}")
    else:
        print(f"Extracted all CVE data from file: {searchsploit_xml_path}")
        try:
            searchsploit_cve_only_df.to_excel(searchsploit_excel_path, index=False)
        except Exception as e:
            sys.exit(f"Error writing Excel file to: {searchsploit_excel_path}")
        else:
            print(f"Excel file written to: {searchsploit_excel_path}")


def filter_cve(GHDB_string: str):
    """ Use for the GHDB_cve_extract() """
    """ Used to filter string data from textualDescription from GHDB data """
    
    GHDB_string = GHDB_string.replace('CVE-','CVE:')
    GHDB_string = GHDB_string.replace('CVE-CVE-','CVE-')

    # dash_match = re.search(r"CVE-\d{4}-\d{4,7}", GHDB_string)
    dash_match = re.search(r"\d{4}-\d{4,7}", GHDB_string)
    cve_id = dash_match.group()
    

    
    return cve_id

          
if __name__ == "__main__":
    #! Credit to https://github.com/nomi-sec/PoC-in-GitHub/
    import config
    app_config, user_config = config.bootstrap()
    
    unique_cves = ('CVE-2016-2183', 'CVE-2023-23375', 'CVE-2023-28304', 'CVE-2020-11022', 'CVE-2020-11023', 'CVE-2022-31777')
    
    download(app_config, user_config)
    extract(app_config)
    response = create_dataframe(app_config)
    GHDB_df = response["data"]
    #! link = link to the database article
    #! ebd = link to the exploit
    
    # enrich_with_exploitdb(GHDB_df, unique_cves)