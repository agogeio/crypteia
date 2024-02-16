import flatdict
import gzip
import json
import os
import pandas as pd
import requests
import shutil
import sys
import time

from urllib.request import urlretrieve

NVD_API_KEY = os.environ.get("NVD_API_KEY")


def calculate_run_time(unique_cves: tuple) -> int:
    """Calculate the run time for data processing"""
    
    print("\n***** Calculate the approximate run time for CVE processing *****\n")
    
    number_of_cves = len(unique_cves)
    nvd_sleep_timer = 6
    
    if 'NVD_API_KEY' not in os.environ:
        print("No NVD API key found, rate limit is 10 requests per minute")
        time_to_process = number_of_cves / 10
        
    elif 'NVD_API_KEY' in os.environ:
        print("NVD API key found, rate limit is 100 requests per minute")
        time_to_process = number_of_cves / 60
        nvd_sleep_timer = 1
        
    else:
        print("Unknown issue processing your NVD API Key, setting default to no API key")
        time_to_process = number_of_cves / 10
        
    print(f'{number_of_cves} unique CVEs processed, this process will take roughly {time_to_process} minutes due to NVD API rate limiting')
    
    return nvd_sleep_timer



#! Need to pull the update logic out of this function and create an update controller that calls the download function
def download(app_config: dict, user_config: dict):
    """ Downloads the EXPLOITDB XML file """
    
    print("\n***** Beginning processing of NVD files *****\n")
    
    nvd_file_paths = []
    nvd_missing_files = []
    
    NVD_DATA_DOWNLOAD_URLS = app_config["download_URLs"]["NVD_DATA_DOWNLOAD_URLS"]
    NVD_DATA_BASE_URL = app_config["download_URLs"]["NVD_DATA_BASE_URL"]
    NVD_DATA_DIR = app_config["NVD_DATA_DIR"]
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    NVD_DATA_AUTO_UPDATE = user_config["NVD_DATA_AUTO_UPDATE"]

    for nvd_url in NVD_DATA_DOWNLOAD_URLS:
                nvd_file_name = nvd_url.split('/')[7][:-3]
                nvd_file_path = NVD_DATA_DIR+nvd_file_name
                nvd_file_paths.append(nvd_file_path)
    

    if NVD_DATA_AUTO_UPDATE == "True":
        
        print("Auto updated of NVD data set to true, downloading NVD data files.")
        print("This may take a while depending on your Internet speed\n")
                
        if not os.path.exists(NVD_DATA_DIR):
                os.makedirs(NVD_DATA_DIR)
                print(f"Creating directory {NVD_DATA_DIR}")
        
        for nvd_url in NVD_DATA_DOWNLOAD_URLS:
            nvd_file_name = nvd_url.split('/')[7][:-3]
            nvd_file_path = NVD_DATA_DIR+nvd_file_name
            nvd_gz_file_path = NVD_DATA_DIR+nvd_file_name+".gz"

            try:
                print(f"Downloading: {nvd_url}")
                urlretrieve(url=nvd_url, filename=nvd_gz_file_path)
                
                with gzip.open(nvd_gz_file_path, 'rb') as nvd_file_path_gz:
                    with open(nvd_file_path, 'wb') as nvd_file_dir:
                        shutil.copyfileobj(nvd_file_path_gz, nvd_file_dir)
                    
                os.remove(nvd_gz_file_path)
            except Exception as e:
                print(f"Error downloading NVD files: {e}")
            finally:
                pass
        
        merge(app_config)
                
    
    elif AUTO_DOWNLOAD_ALL == "True":
        
        if not os.path.exists(NVD_DATA_DIR):
                os.makedirs(NVD_DATA_DIR)
                print(f"Creating directory {NVD_DATA_DIR}")
        
        for nvd_file_path in nvd_file_paths:
            if os.path.exists(nvd_file_path):
                pass
                # print(f"Found: {nvd_file_path}")
            elif not os.path.exists(nvd_file_path):
                print(f"Not Found: {nvd_file_path}")
                nvd_missing_files.append(nvd_file_path)
        
        if len(nvd_missing_files) > 0:
            
            print(f"{len(nvd_missing_files)} NVD data files missing, starting download")
            
            for missing_file in nvd_missing_files:
                nvd_file_name = missing_file.split('/')[3]
                nvd_file_path = NVD_DATA_DIR+nvd_file_name
                nvd_gz_file_path = NVD_DATA_DIR+nvd_file_name+".gz"
                nvd_url = NVD_DATA_BASE_URL+nvd_file_name+".gz"
                
                try:
                    print(f"Downloading: {nvd_url}")
                    urlretrieve(url=nvd_url, filename=nvd_gz_file_path)
                    
                    with gzip.open(nvd_gz_file_path, 'rb') as nvd_file_path_gz:
                        with open(nvd_file_path, 'wb') as nvd_file_dir:
                            shutil.copyfileobj(nvd_file_path_gz, nvd_file_dir)
                        
                    os.remove(nvd_gz_file_path)
                except Exception as e:
                    print(f"Error downloading NVD files: {e}")
                finally:
                    pass
                    
            merge(app_config)
                    
        else:
            print("No NVD files missing, if you would like to download fresh files set ")
            print('NVD_DATA_AUTO_UPDATE flag in the user_config.json file to "True"')
    
    elif NVD_DATA_AUTO_UPDATE == "False":
        print("Auto Update NVD = False, Auto Download All = True")


def extract_cvss_data(nvd_data: pd.DataFrame) -> dict:
    """ Extract needed CVE data from the NVD dataset """
    # print("\n***** Extract needed CVE data from the NVD dataset *****\n")
    
    keys = nvd_data.keys()
    cvss_data = {}
    
    if "cvssV2" in keys:
        cvss_data["version"] = nvd_data["cvssV2"]["version"]
        cvss_data["baseScore"] = nvd_data["cvssV2"]["baseScore"]
        cvss_data["baseSeverity"] = nvd_data["severity"]
        cvss_data["attackVector"] = nvd_data["cvssV2"]["accessVector"]
        cvss_data["attackComplexity"] = nvd_data["cvssV2"]["accessComplexity"]
        cvss_data["vectorString"] = nvd_data["cvssV2"]["vectorString"]
        
    elif "cvssV3" in keys:
        cvss_data["version"] = nvd_data["cvssV3"]["version"]
        cvss_data["baseScore"] = nvd_data["cvssV3"]["baseScore"]
        cvss_data["baseSeverity"] = nvd_data["cvssV3"]["baseSeverity"]
        cvss_data["attackVector"] = nvd_data["cvssV3"]["attackVector"]
        cvss_data["attackComplexity"] = nvd_data["cvssV3"]["attackComplexity"]
        cvss_data["vectorString"] = nvd_data["cvssV3"]["vectorString"]

    return cvss_data


def nvd_controller(app_config: dict, user_config: dict, unique_cves: tuple) -> list:
    """ Manage flow control if data will be pulled from the API or locally """

    USE_NVD_API = user_config['USE_NVD_API']
    USE_NVD_LOCAL = user_config['USE_NVD_LOCAL']
    
    print("\n***** Entering load controller for NVD data processing *****\n")
    
    if USE_NVD_API == 'True' and USE_NVD_LOCAL == 'True':
        sys.exit('There is an error in your configuration file: USE_NVD_API and USE_NVD_LOCAL are both set to True, only one can be set to True.')
    
    elif USE_NVD_API == 'False' and USE_NVD_LOCAL == 'False':
        sys.exit('There is an error in your configuration file: USE_NVD_API and USE_NVD_LOCAL are both set to False, only one can be set to False.')
    
    elif USE_NVD_API == 'True':
        
        #? If using the API, call load_from_api function
        print("\n***** Configuration set for NVD API use, this could take an extensive period of time for a large number of CVEs *****\n")
        
        nvd_sleep_timer = calculate_run_time(unique_cves)
        nvd_data = load_from_api(app_config, unique_cves, nvd_sleep_timer)
        return nvd_data
        
    elif USE_NVD_LOCAL == 'True':
        print("\n***** Configuration set for NVD API use, this will take several GB memory to load the NVD data into memory *****\n")
 
        #? If using local data store load the data from the file and get the Dataframe
        nvd_df = load_from_local(app_config)
        
        #? Pass the Dataframe and params to extract the needed data
        nvd_data = process_local(app_config, user_config, unique_cves, nvd_df)

        #? Return the report data back in a common format.
        print("Returning local NVD data report")
        return nvd_data


def load_from_api(app_config: dict, unique_cves: tuple, nvd_sleep_timer: int = 6) -> list:
    """ Extracts data from the National Vulnerability Database """
    
    print("\n***** Using NVD API for CVE processing *****\n")
    
    cve_list = []
    counter = 1
    HEADER = {'apiKey': NVD_API_KEY}
    NVD_URL = app_config["download_URLs"]["NVD_API_BASE_URL"]
    
    print(f"NVD sleep timer is set to {nvd_sleep_timer} second(s) to account for API rate limiting \n")
    
    for cve in unique_cves:
        total_url = NVD_URL+cve      
        baseScore = ""
        baseSeverity = ""
        attackVector = ""
        attackComplexity = ""

        # print(f'Processing CVE id: {cve} with URL of: {total_url}')        
        #! Modified CVE
        # total_url = NVD_URL+'CVE-2017-0170' 
        #! https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0170
        
        #! Rejected CVE
        # total_url = NVD_URL+'CVE-2023-4128' 
        #! https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-4128
        
        #! No baseSeverity
        #! https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-2808
        # total_url = NVD_URL+'CVE-2015-2808' 
                
        try:
            response = requests.get(url = total_url, headers = HEADER)
            response_json = response.json()
            print(f"[{counter}] Processing: {total_url}")
            counter += 1
            if response_json["totalResults"] == 0:
                cve_list.append([cve, "Invalid", "None", "None", "None", "None", "None"])
            else:            
                vulnStatus = response_json["vulnerabilities"][0]['cve']['vulnStatus']
                if vulnStatus == "Rejected":
                    cve_list.append([cve, vulnStatus, "None", "None", "None", "None"])
                    
                elif vulnStatus != "Rejected":
                    cve_keys = response_json["vulnerabilities"][0]['cve']['metrics'].keys()
                    if "cvssMetricV31" in cve_keys:
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        vectorString = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString']
                        attackVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
                        attackComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity, vectorString])
                    elif "cvssMetricV30" in cve_keys:
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                        vectorString = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['vectorString']
                        attackVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
                        attackComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity, vectorString])
                    elif "cvssMetricV2" in cve_keys:
                        cvssData_keys = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'].keys()
                        if "baseSeverity" in cvssData_keys:
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                            vectorString = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['vectorString']
                            accessVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
                            accessComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
                            cve_list.append([cve, vulnStatus, baseScore, baseSeverity, accessVector, accessComplexity, vectorString])
                        elif "baseSeverity" not in cvssData_keys:
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            vectorString = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['vectorString']
                            accessVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
                            accessComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
                            cve_list.append([cve, vulnStatus, baseScore, "None", accessVector, accessComplexity, vectorString])
                    else:
                        print('Unknown CVSS standard')
            time.sleep(nvd_sleep_timer)
        except Exception as e:
            print(f"Error Processing: {total_url}")
            print(f'Processing Error was: {e}')
        finally:
            pass
            # Nothing to do in finally

    return cve_list


def load_from_local(app_config: dict) -> pd.DataFrame: #, unique_cves: tuple
    """ Reading data from the local NVD data source """
    
    NVD_DATA_DIR = app_config["NVD_DATA_DIR"]
    NVD_FILE = app_config["NVD_FILE"]
    NVD_PATH = NVD_DATA_DIR+NVD_FILE
    
    print("\n***** Loading local NVD database file, this may take several seconds *****\n")
    
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


def merge(app_config: dict) -> None:
    """ Merge the downloaded NVD JSON files into a single JSON document """
    
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


def process_local(app_config: dict, user_config: dict, unique_cves: tuple, nvd_df: pd.DataFrame) -> list:
    """ Takes application & user configs and extracts CVE information from the supplied dataframe """
    print("\n***** Beginning data extraction from the local NVD database *****\n")
    
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
    import config
    app_config, user_config = config.bootstrap()
    TEST_CVE_IDs = user_config["TEST_CVE_IDs"]    
    # merge(app_config)
    nvd_data = nvd_controller(app_config, user_config, TEST_CVE_IDs)
    print(nvd_data)
    
    