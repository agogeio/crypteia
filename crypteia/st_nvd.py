import flatdict
import json
import os
import pandas as pd
import requests
import sys
import time

from crypteia import config, utils

NVD_API_KEY = os.environ.get("NVD_API_KEY")

THREAT_INTEL_TYPE = 'NVD'

ACTIONS = {
    "download": "download",
    "none": "none",
    "terminate" : "terminate"
}

STATUS_ERROR = 400
STATUS_TERMINATE = 500
STATUS_OK = 200

# MARK: check_missing_files
#! Updated but not currently used
def check_missing_files(nvd_file_paths) -> dict:
    """
    Accepts a list of NVD file paths and tests for their existence

    Args:
        nvd_file_paths (_type_): A list of NVD file paths

    Returns:
        dict: with keys: data, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """
    app_config, user_config = config.bootstrap()
    
    
    nvd_missing_files = []
    status = ""
    
    for nvd_file_path in nvd_file_paths:
        try:
            if not os.path.exists(nvd_file_path):
                print(f"Not Found: {nvd_file_path}")
        except Exception as e:
            error = {e}
            status = STATUS_TERMINATE
        else:
            nvd_missing_files.append(nvd_file_path)
            status = STATUS_OK
    data = nvd_missing_files
    response = {"data": data, "error": error, "message": "Missing NVD files analyzed", "status": status }
    return response


#  MARK: download
#! Need to fix responses to match dict output
def download(app_config: dict, user_config: dict) -> dict:
    """
    Accepts the app_config and user_config and begins downloading the NVD 
    data set. 

    Args:
        app_config (dict): the app_config file is located at ./config/app_config.json
        user_config (dict): the user_config file is located at ./config/user_config.json
        
    Returns:
        dict: with keys: data, error (if present), message, report_columns, status (200 for ok, 400 for error, 500 for terminate)
    """
   
    nvd_download_data = []
    
    NVD_DATA_DOWNLOAD_URLS = app_config["download_URLs"]["NVD_DATA_DOWNLOAD_URLS"]
    NVD_DATA_DIR = app_config["NVD_DATA_DIR"]
    
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    NVD_DATA_AUTO_UPDATE = user_config["NVD_DATA_AUTO_UPDATE"]
    
    merge = False
    
    #* Validates the NVD directory exists or creates it 
    utils.directory_manager(NVD_DATA_DIR)

    #* Parses out the NVD download URLs to build the appropriate file names and paths
    for nvd_url in NVD_DATA_DOWNLOAD_URLS:
        nvd_file_name = nvd_url.split('/')[7][:-3]
        nvd_file_path = NVD_DATA_DIR+nvd_file_name
        nvd_gz_file_path = NVD_DATA_DIR+nvd_file_name+".gz"
        
        nvd_data = {
            "nvd_url": nvd_url,
            "nvd_file_path": nvd_file_path,
            "nvd_gz_file_path": nvd_gz_file_path
        }

        nvd_download_data.append(nvd_data)

    for data in nvd_download_data:
        #* Checks file age and config settings to see if files should be downloaded
        response = utils.file_manager(AUTO_DOWNLOAD_ALL, NVD_DATA_AUTO_UPDATE, data["nvd_file_path"])
        if "error" in response.keys():
            print(f"{response["error"]}")
        elif "error" not in response.keys():
            if response['action'] == 'download':
                response = utils.file_download(data["nvd_url"], data["nvd_gz_file_path"])
                utils.un_gzip(data["nvd_gz_file_path"], data["nvd_file_path"])
                print(f"{response['message']}")
                merge = True
            elif response['action'] == 'none':
                print(f"{response['message']}")
        else:
            sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")

    #! I don't love this, need to put merge on it's own        
    if merge == True: filter_and_merge(app_config)


# MARK: extract_cvss_data
#! Need to fix responses to match dict output
def extract_cvss_data(nvd_data: pd.DataFrame) -> dict:
    """ Extract needed CVE data from the NVD dataset """
    # print("\n***** Extract needed CVE data from the NVD dataset *****\n")
    
    keys = nvd_data.keys()
    cvss_data = {}
    cvss_version = ""
    
    if "cvssV2" in keys:
        cvss_version = "cvssV2"
        cvss_data["version"] = nvd_data["cvssV2"]["version"]
        cvss_data["baseScore"] = nvd_data["cvssV2"]["baseScore"]
        cvss_data["baseSeverity"] = nvd_data["severity"]
        cvss_data["attackVector"] = nvd_data["cvssV2"]["accessVector"]
        cvss_data["attackComplexity"] = nvd_data["cvssV2"]["accessComplexity"]
        cvss_data["vectorString"] = nvd_data["cvssV2"]["vectorString"]
        
    elif "cvssV3" in keys:
        cvss_version = "cvssV3"
        cvss_data["version"] = nvd_data["cvssV3"]["version"]
        cvss_data["baseScore"] = nvd_data["cvssV3"]["baseScore"]
        cvss_data["baseSeverity"] = nvd_data["cvssV3"]["baseSeverity"]
        cvss_data["attackVector"] = nvd_data["cvssV3"]["attackVector"]
        cvss_data["attackComplexity"] = nvd_data["cvssV3"]["attackComplexity"]
        cvss_data["vectorString"] = nvd_data["cvssV3"]["vectorString"]

    #! Setup for web use
    # message = f"The CVSS version is {cvss_version}"
    # status = STATUS_OK
    # response = {"data": cvss_data, "message": message, "status": status }
    
    return cvss_data


# MARK: filter_and_merge
#! Need to fix responses to match dict output
def filter_and_merge(app_config: dict) -> None:
    """
    Reads the app_config.json file for the base directory, identifies all
    json files in the directory and filters and merges the NVD data set.

    Args:
        app_config (dict): the app_config file is located at ./config/app_config.json
    """
    
    print("\n***** Beginning the merge process of NVD data, this could take some time *****\n")

    nvd_data_dir = app_config["NVD_DATA_DIR"]
    nvd_data_files = app_config["NVD_DATA_FILES"]
    nvd_master_file = app_config["NVD_FILE"] 
    extracted_nvd_data = {} 
    nvd_database_list = []
    nvd_database = {}
    
    for data_file in nvd_data_files:
        nvd_file_path = nvd_data_dir+data_file
        try:
            with open(nvd_file_path, encoding='utf-8') as nvd_file:
                nvd_data = nvd_file.read()
                nvd_json = json.loads(nvd_data)
        except Exception as e:
            print(f"File processing error: {e}")
        else:
            for nvd_item in nvd_json['CVE_Items']:
                nvd_cve_items = nvd_item["cve"]["CVE_data_meta"]['ID']
                nvd_cve_id = {"ID": nvd_cve_items}
                nvd_cve_description_data = nvd_item["cve"]["description"]["description_data"][0]["value"]
                
                if "Rejected" in nvd_cve_description_data:
                    vulnStatus = {"vulnStatus" : "Rejected"}
                else:
                    vulnStatus = {"vulnStatus" : "Processed by NVD"}
                    
                nvd_impact_items = nvd_item["impact"]
                extracted_nvd_data = nvd_cve_id | vulnStatus | nvd_impact_items
                nvd_database_list.append(extracted_nvd_data)

    nvd_database["nvd_database"] = nvd_database_list

    try:
        nvd_master_file_path = nvd_data_dir+nvd_master_file
        with open(nvd_master_file_path, 'w', encoding='utf-8') as nvd_out:
            nvd_out.writelines(json.dumps(nvd_database))
    except Exception as e:
        print(f"Error writing nvd_master.json: {e}")
    else:
        print(f"File {nvd_master_file_path} with {len(nvd_database["nvd_database"])} records written to the filesystem")


# MARK: nvd_controller
#! Need to fix responses to match dict output
def nvd_controller(app_config: dict, unique_cves: tuple) -> list:
    """ Manage flow control if data will be pulled from the API or locally """

    USE_NVD_LOCAL = 'True'
    
    # print("\n***** Entering load controller for NVD data processing *****\n")
        
    if USE_NVD_LOCAL == 'True':
        # print("\n***** The user_config.json file variable USE_NVD_LOCAL is set to True, this will take several GB memory *****\n")
 
        #? If using local data store load the data from the file and get the Dataframe
        nvd_df = load_from_local(app_config)
        
        #? Pass the Dataframe and params to extract the needed data
        nvd_data = process_local(unique_cves, nvd_df)

        #? Return the report data back in a common format.
        print("Returning local NVD data report")
        return nvd_data





#MARK: load_from_local
#! Need to fix responses to match dict output
def load_from_local(app_config: dict) -> pd.DataFrame: #, unique_cves: tuple
    """ Reading data from the local NVD data source """
    
    NVD_DATA_DIR = app_config["NVD_DATA_DIR"]
    NVD_FILE = app_config["NVD_FILE"]
    NVD_PATH = NVD_DATA_DIR+NVD_FILE
    
    # print("\n***** Loading local NVD database file, this may take several seconds *****\n")
    
    try:
        nvd_file_size = os.path.getsize(NVD_PATH)
        nvd_file_size = int((nvd_file_size / 1024)/1024)
        print(f'\n***** NVD file size on disk is: {nvd_file_size} MB *****\n')
        
        with open(NVD_PATH, encoding='utf-8') as nvd_file:
            nvd_data = json.load(nvd_file)
            nvd_data = flatdict.FlatDict(nvd_data)
            nvd_data = nvd_data.as_dict()
            nvd_df = pd.DataFrame(nvd_data['nvd_database'])
    except Exception as e:
        print(f'There was an error in the process of loading the NVD data file: {e}')    
    else:
        return nvd_df


#MARK: process_local
#! Need to fix responses to match dict output
def process_local(unique_cves: tuple, nvd_df: pd.DataFrame) -> list:
    """ Takes application & user configs and extracts CVE information from the supplied dataframe """
    # print("\n***** Beginning data extraction from the local NVD database *****\n")
    
    cve_list = []
    
    for cve in unique_cves:
        # print(f"\nProcessing CVE: {cve}")
        cve_record = nvd_df.loc[nvd_df['ID'] == cve]
         
        if len(cve_record) < 1:
            print(f"Invalid CVE record submitted: {cve}")
        elif len(cve_record) == 1:

            vulnStatus  = cve_record["vulnStatus"].loc[cve_record.index[0]]
            #? You need to make sure you're getting the index of the CURRENT record.
            #? You need to save this index for a query later when you're checking 
            #? if the record is NaN
            
            index = cve_record.index[0]
            
            baseMetricV2_present = cve_record["baseMetricV2"].notnull()
            baseMetricV3_present = cve_record["baseMetricV3"].notnull()
            #! Prep for CVSS v4, the merge function will need to be updated
            # baseMetricV4_present = cve_record["baseMetricV4"].notnull()
            
            if vulnStatus == "Rejected":
                print(f'CVE ID {cve}  was: {vulnStatus}')
                cve_list.append([cve, vulnStatus, 'None', 'None', 'None', 'None', 'None'])
            #? Strangely you need the index value for these queries
            #? Shocked that this isn't the "current index"
            #! Prep for CVSS v4, the merge function will need to be updated
            # elif baseMetricV4_present[index] == True:
            #     print(f'CVE ID: {cve} has CVSS v4 data')
            #     cvss_data = cve_record["baseMetricV4"].apply(extract_cvss_data)
            elif baseMetricV3_present[index] == True:
                # print(f'CVE ID: {cve} has CVSS v3 data')
                # cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity, vectorString])
                
                cvss_data = cve_record["baseMetricV3"].apply(extract_cvss_data)
                cvss_data = cvss_data.to_dict()
                cvss_data = cvss_data[index]

                # cvss_version = cvss_data["version"]
                baseScore = cvss_data["baseScore"]
                baseSeverity = cvss_data["baseSeverity"]
                attackVector = cvss_data["attackVector"]
                attackComplexity = cvss_data["attackComplexity"]
                vectorString = cvss_data["vectorString"]
                
                cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity, vectorString])
                 
            elif baseMetricV2_present[index] == True:
                # print(f'CVE ID: {cve} has CVSS v2 data')
                # cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity, vectorString])
                
                cvss_data = cve_record["baseMetricV2"].apply(extract_cvss_data)
                cvss_data = cvss_data.to_dict()
                cvss_data = cvss_data[index]
                
                # cvss_version = cvss_data["version"]
                baseScore = cvss_data["baseScore"]
                baseSeverity = cvss_data["baseSeverity"]
                attackVector = cvss_data["attackVector"]
                attackComplexity = cvss_data["attackComplexity"]
                vectorString = cvss_data["vectorString"]
                
                cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity, vectorString])

    return cve_list



if __name__ == "__main__":
    
    #! Test CVEs needs to be a tuple
    # TEST_CVE_IDs = ("CVE-1999-0001", "CVE-2021-27103", "CVE-2021-21017", "CVE-2017-0170", "CVE-2023-4128", "CVE-2015-2808", "CVE-2023-40481")
    
    # import config
    # app_config, user_config = config.bootstrap()
    # download(app_config, user_config)
    
    # nvd_data = nvd_controller(app_config, user_config, TEST_CVE_IDs)
    # print(nvd_data)
    
    pass