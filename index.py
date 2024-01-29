import gzip
import json
import os
import pandas as pd
import requests
import shutil
import sys
import time


# from os.path import exists, isfile
from datetime import datetime
from urllib.request import urlretrieve

NVD_API_KEY = os.environ.get("NVD_API_KEY")
VULDB_API_KEY = os.environ.get("VULDB_API_KEY")


cve_list = []
cve_tuple = ()
vuln_medium = ()
vuln_high = ()
vuln_critical = ()


def cve_config_bootstrap():
    """Bootstrap configuration files"""
    
    print("\n***** Beginning processing of configuration files *****\n")
    
    app_config_file = "./config/app_config.json"
    user_config_file = "./config/user_config.json"
    
    if os.path.isfile(app_config_file):
        print("Application configuration file located")
    
        try:
            with open(app_config_file, 'r', encoding='utf-8') as app_config:
                app_config_obj = json.load(app_config)
        except Exception as e:
            print(f"Error accessing the application configuration file: {e}")
        finally:
            print("Application configuration settings read")

    
    if os.path.isfile(user_config_file):
        print("User config file located")
        try:
            with open(user_config_file, 'r', encoding='utf-8') as user_config:
                user_config_obj = json.load(user_config)
        except Exception as e:
            print(f"Error accessing the user configuration file: {e}")
        finally:
            print("User configuration settings read")

    return app_config_obj, user_config_obj


def download_KEV_file(app_config: dict, user_config: dict):
    """ Downloads the KEV JSON file """
    
    print("\n***** Beginning processing of CISA KEV files *****\n")
    
    CISA_KEV_DOWNLOAD_URL = app_config["download_URLs"]["CISA_KEV_DOWNLOAD_URL"]
    CISA_KEV_DIR=app_config["CISA_KEV_DIR"]
    CISA_KEV_FILE=app_config["CISA_KEV_FILE"]
    CISA_KEV_PATH=CISA_KEV_DIR+CISA_KEV_FILE
    
    CISA_KEV_download = False
    
    if os.path.isfile(CISA_KEV_PATH):
        print(f"Existing CISA KEV file located at: {CISA_KEV_PATH}")
        if user_config["AUTO_UPDATE_KEV_DATA"] == "True":
            print("CISA KEV is configured for auto update, downloading CISA KEV update")
            CISA_KEV_download = True
        elif user_config["AUTO_UPDATE_KEV_DATA"] == "False":
            print("CISA KEV is not configured for auto update, no CISA KEV update will be downloaded.")
            print("Warning, you may be using an outdated version of the CISA KEV list")
    elif not os.path.isfile(CISA_KEV_PATH):
        print(f"No existing CISA KEV file found at location: {CISA_KEV_PATH}")
        if user_config["AUTO_DOWNLOAD_ALL"] == "True":
            print(f"Auto download set to {user_config["AUTO_DOWNLOAD_ALL"]}, CISA KEV will be downloaded")
            CISA_KEV_download = True
        elif user_config["AUTO_DOWNLOAD_ALL"] == "False":
            print(f"Auto download set to {user_config["AUTO_DOWNLOAD_ALL"]}, CISA KEV will not be downloaded")    
        else:
            sys.exit("No CISA KEV File found, error processing user config settings, terminating program")
        
    if CISA_KEV_download == True:
        try:
            if not os.path.exists(CISA_KEV_DIR):
                os.makedirs(CISA_KEV_DIR)
                print(f"Creating directory {CISA_KEV_DIR}")
            
            urlretrieve(url=CISA_KEV_DOWNLOAD_URL, filename=CISA_KEV_PATH)
        except Exception as e:
            print("The following error ocurred: ", e )
            sys.exit("Failed to process CISA KEV file")
        finally:
            # No code to execute on failure
            pass


def download_EPSS_file(app_config: dict, user_config: dict):
    """ Downloads the EPSS C file """
    
    print("\n***** Beginning processing of EPSS files *****\n")
    
    EPSS_DOWNLOAD_URL = app_config["download_URLs"]["EPSS_DOWNLOAD_URL"]
    EPSS_DIR=app_config["EPSS_DIR"]
    EPSS_FILE=app_config["EPSS_FILE"]
    EPSS_GZ_FILE=app_config["EPSS_GZ_FILE"]
    EPSS_GZ_PATH=EPSS_DIR+EPSS_GZ_FILE
    EPSS_PATH=EPSS_DIR+EPSS_FILE
    
    EPSS_download = False
    
    if os.path.isfile(EPSS_PATH):
        print(f"Existing EPSS file located at: {EPSS_PATH}")
        if user_config["AUTO_UPDATE_EPSS_DATA"] == "True":
            print("EPSS is configured for auto update, downloading EPSS update")
            EPSS_download = True
        elif user_config["AUTO_UPDATE_EPSS_DATA"] == "False":
            print("EPSS is not configured for auto update, no EPSS update will be downloaded.")
            print("Warning, you may be using outdated EPSS data")
    elif not os.path.isfile(EPSS_PATH):
        print(f"No existing EPSS file found at location: {EPSS_PATH}")
        if user_config["AUTO_DOWNLOAD_ALL"] == "True":
            print(f"Auto download set to {user_config["AUTO_DOWNLOAD_ALL"]}, EPSS will be downloaded")
            EPSS_download = True
        elif user_config["AUTO_DOWNLOAD_ALL"] == "False":
            print(f"Auto download set to {user_config["AUTO_DOWNLOAD_ALL"]}, EPSS will not be downloaded")    
        else:
            sys.exit("No EPSS file found, error processing user config settings, terminating program")
        
    if EPSS_download == True:
        try:
            if not os.path.exists(EPSS_DIR):
                os.makedirs(EPSS_DIR)
                print(f"Creating directory {EPSS_DIR}")

            urlretrieve(url=EPSS_DOWNLOAD_URL, filename=EPSS_GZ_PATH)

            with gzip.open(EPSS_GZ_PATH, 'rb') as epss_gz:
                with open(EPSS_PATH, 'wb') as epss_csv:
                    shutil.copyfileobj(epss_gz, epss_csv)

            os.remove(EPSS_GZ_PATH)
        except Exception as e:
            print("The following error ocurred: ", e )
            sys.exit("Failed to process EPSS file")
        finally:
            # No code to execute on failure
            pass

        
def download_EXPLOITDB_file(app_config: dict, user_config: dict):
    """ Downloads the EXPLOITDB XML file """
    
    print("\n***** Beginning processing of EPSS files *****\n")
    
    EXPLOITDB_DOWNLOAD_URL = app_config["download_URLs"]["EXPLOITDB_DOWNLOAD_URL"]
    EXPLOITDB_DIR=app_config["EXPLOITDB_DIR"]
    EXPLOITDB_FILE=app_config["EXPLOITDB_FILE"]
    EXPLOITDB_PATH=EXPLOITDB_DIR+EXPLOITDB_FILE
    
    ExploitDB_download = False
    
    if os.path.isfile(EXPLOITDB_PATH):
        print(f"Existing ExploitDB XML file located at: {EXPLOITDB_PATH}")
        if user_config["AUTO_UPDATE_EXPLOITDB_DATA"] == "True":
            print("ExploitDB is configured for auto update, downloading ExploitDB data.")
            ExploitDB_download = True
        elif user_config["AUTO_UPDATE_KEV_DATA"] == "False":
            print("ExploitDB is not configured for auto update, no ExploitDB update will be downloaded.")
            print("Warning: you may be using an outdated version of the ExploitDB data set")
    elif not os.path.isfile(EXPLOITDB_PATH):
        print(f"No existing ExploitDB file found at location: {EXPLOITDB_PATH}")
        if user_config["AUTO_DOWNLOAD_ALL"] == "True":
            print(f"Auto download set to {user_config["AUTO_DOWNLOAD_ALL"]}, ExploitDB data will be downloaded")
            ExploitDB_download = True
        elif user_config["AUTO_DOWNLOAD_ALL"] == "False":
            print(f"Auto download set to {user_config["AUTO_DOWNLOAD_ALL"]}, ExploitDB data will not be downloaded")    
        else:
            sys.exit("No ExploitDB File found, error processing user config settings, terminating program")
        
    if ExploitDB_download == True:
        try:
            if not os.path.exists(EXPLOITDB_DIR):
                os.makedirs(EXPLOITDB_DIR)
                print(f"Creating directory {EXPLOITDB_DIR}")
            
            urlretrieve(url=EXPLOITDB_DOWNLOAD_URL, filename=EXPLOITDB_PATH)
        except Exception as e:
            print("The following error ocurred: ", e )
            sys.exit("Failed to process ExploitDB file")
        finally:
            # No code to execute on failure
            pass       


def download_NVD_files(app_config: dict, user_config: dict):
    """ Downloads the EXPLOITDB XML file """
    
    print("\n***** Beginning processing of NVD files *****\n")
    
    nvd_file_paths = []
    nvd_missing_files = []
    
    NVD_DATA_DOWNLOAD_URLS = app_config["download_URLs"]["NVD_DATA_DOWNLOAD_URLS"]
    NVD_DATA_BASE_URL = app_config["download_URLs"]["NVD_DATA_BASE_URL"]
    NVD_DATA_DIR = app_config["NVD_DATA_DIR"]
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    AUTO_UPDATE_NVD_DATA = user_config["AUTO_UPDATE_NVD_DATA"]

    for nvd_url in NVD_DATA_DOWNLOAD_URLS:
                nvd_file_name = nvd_url.split('/')[7][:-3]
                nvd_file_path = NVD_DATA_DIR+nvd_file_name
                nvd_file_paths.append(nvd_file_path)
    

    if AUTO_UPDATE_NVD_DATA == "True":
        
        print("Auto updated of NVD data set to true, downloading NVD data files.")
        print("This may take a while depending on your Internet speed")
                
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
                # Nothing to do always
    
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
                    # Nothing to do always
        else:
            print("No NVD files missing, if you would like to download fresh files set ")
            print('AUTO_UPDATE_NVD_DATA flag in the user_config.json file to "True"')
                
            
    
    elif AUTO_UPDATE_NVD_DATA == "False":
        print("Auto Update NVD = False, Auto Download All = True")


    # for URL in NVD_DATA_DOWNLOAD_URLS:
    #     nvd_data_files_gz.append(URL.split('/')[7])
        
    # for working_nvd_file in nvd_data_files_gz:
    #     nvd_data_files.append(working_nvd_file[:-3])
    
    # for working_nvd_file in nvd_data_files:
    #     working_nvd_file_path = app_config['NVD_DATA_DIR']+working_nvd_file
        
    #     if os.path.isfile(working_nvd_file_path):
    #         print(f"File found: {working_nvd_file_path}")
    #     else:
    #         print(f"Not found: {working_nvd_file_path}")
    #         missing_url = NVD_DATA_BASE_URL+working_nvd_file+".gz"
            
    #         nvd_missing_urls.append(missing_url)
    #         nvd_missing_files.append(working_nvd_file_path)
            

def extract_CVEs(app_config: dict, user_config: dict):
    """ Extracts CVEs from provided report, returns data as tuple """
    
    print("\n***** Beginning processing of user supplied vulnerability file *****\n")
 
    USER_VULNERABILITY_IMPORT_REPORT_DIR = user_config["USER_VULNERABILITY_IMPORT_REPORT_DIR"]
    USER_VULNERABILITY_IMPORT_REPORT_NAME = user_config["USER_VULNERABILITY_IMPORT_REPORT_NAME"]
    USER_VULNERABILITY_SHEET_NAME = user_config["USER_VULNERABILITY_SHEET_NAME"]
    USER_VULNERABILITY_COLUMN_NAME = user_config["USER_VULNERABILITY_COLUMN_NAME"]
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    
    vulnerability_report_path = USER_VULNERABILITY_IMPORT_REPORT_DIR+USER_VULNERABILITY_IMPORT_REPORT_NAME
    
    
    if not os.path.exists(USER_VULNERABILITY_IMPORT_REPORT_DIR):
        sys.exit(f'''There is no {USER_VULNERABILITY_IMPORT_REPORT_DIR} directory, please create it and place the vulnerability report named {USER_VULNERABILITY_IMPORT_REPORT_NAME} in the directory.  Terminating program.''')
        
    else:
        try:
            print(f"Processing report: {vulnerability_report_path}")
            df = pd.read_excel(vulnerability_report_path, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=[USER_VULNERABILITY_COLUMN_NAME])
            #! df.dropna() will drop the NaN from the specified column
            df = df.dropna(subset=cols[0])
        except Exception as e:
            print("There was an error:", e)
        finally:
            # pass
            np_cve = pd.DataFrame(df[USER_VULNERABILITY_COLUMN_NAME].unique())
        
            for cve_collection in np_cve[0]:
                split_cve = cve_collection.split(',')
                for cve in split_cve:
                    cve_list.append(cve)
            cve_tuple = tuple(cve_list)
        return cve_tuple


def calculate_NVD_run_time(CVEs: tuple):
    """Calculate the run time for data processing"""
    
    print("\n***** Calculate the approximate run time for CVE processing *****\n")
    
    number_of_cves = len(CVEs)
    nvd_sleep_timer = 6
    
    if 'NVD_API_KEY' not in os.environ:
        print("No NVD API key found, rate limit is 10 requests per minute")
        time_to_process = number_of_cves / 10
        
    elif 'NVD_API_KEY' in os.environ:
        print("NVD API key found, rate limit is 100 requests per minute")
        time_to_process = number_of_cves / 60
        nvd_sleep_timer = .6
        
    else:
        print("Unknown issue processing your NVD API Key, setting default to no API key")
        time_to_process = number_of_cves / 10
        
    print(f'{number_of_cves} unique CVEs processed, this process will take roughly {time_to_process} minutes due to NVD API rate limiting')
    
    return nvd_sleep_timer


def load_CVE_from_NVD(app_config: dict, user_config: dict, cve_tuple: tuple, nvd_sleep_timer: 6):
    """ Extracts data from the National Vulnerability Database """
    
    print("\n***** Using NVD API for CVE processing *****\n")
    
    cve_list = []
    counter = 1
    HEADER = {'apiKey': NVD_API_KEY}
    NVD_URL = app_config["download_URLs"]["NVD_API_BASE_URL"]
    
    print(f"NVD sleep timer is set to {nvd_sleep_timer}")
    
    for cve in cve_tuple:
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
                # print(f'{cve} invalid with totalResults of 0')
                cve_list.append([cve, "Invalid", "None", "None", "None", "None"])
            else:            
                vulnStatus = response_json["vulnerabilities"][0]['cve']['vulnStatus']
                descriptions_value = response_json["vulnerabilities"][0]['cve']['descriptions'][0]['value']
                if vulnStatus == "Rejected":
                    # print(f'{cve} was {vulnStatus} by NVD with a description of: {descriptions_value}')
                    cve_list.append([cve, vulnStatus, "None", "None", "None", "None"])
                    
                elif vulnStatus != "Rejected":
                    cve_keys = response_json["vulnerabilities"][0]['cve']['metrics'].keys()
                    if "cvssMetricV31" in cve_keys:
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        attackVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
                        attackComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
                        # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity])
                    elif "cvssMetricV30" in cve_keys:
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                        attackVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
                        attackComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
                        # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity])
                    elif "cvssMetricV2" in cve_keys:
                        cvssData_keys = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'].keys()
                        if "baseSeverity" in cvssData_keys:
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                            accessVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
                            accessComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
                            # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                            cve_list.append([cve, vulnStatus, baseScore, baseSeverity, accessVector, accessComplexity])
                        elif "baseSeverity" not in cvssData_keys:
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            accessVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
                            accessComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
                            # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !None!')
                            cve_list.append([cve, vulnStatus, baseScore, "None", accessVector, accessComplexity])
                    else:
                        print('Unknown CVSS standard')
            time.sleep(nvd_sleep_timer)
        except Exception as e:
            print(f"Error Processing: {total_url}")
            print(f'CVE Processing Error: {e}')
        finally:
            pass
            # Nothing to do in finally

    return cve_list


def load_KEV_data(app_config: dict):
    """ Returns the KEV dataset as a pd.Dataframe """
    
    print("\n***** Using local CISA KEV file to load into DataFrame *****\n")
    
    KEV_filename = app_config["CISA_KEV_DIR"]+app_config["CISA_KEV_FILE"]
    
    try:
        with open(KEV_filename) as KEV_file:
            KEV_data = KEV_file.read()
            KEV_json = json.loads(KEV_data)
            KEV_df =  pd.DataFrame.from_dict(KEV_json["vulnerabilities"])
    except Exception as e:
        print(f'Error loading KEV File: {e}')
        return e
    finally:
        pass
        
    return KEV_df


def build_KEV_report(KEV_df: pd.DataFrame, cveIDs: list):  
    
    print("\n***** Enhancing report data with CISA KEV data *****\n")
    
    cves = cveIDs      
    for cve in cves:
        current_cve = cve[0]
        result = KEV_df.loc[KEV_df["cveID"] == cve[0]]
        if len(result.values) == 0:
            # print(f"{current_cve} was not found in the KEV database")
            cve.append("Not in KEV")
            cve.append("Not in KEV")
        else:
            ransomwareUse = result["knownRansomwareCampaignUse"].values
            # print(f'{current_cve} Found in KEV database ransomwareStatus is: {ransomwareUse[0]}')
            cve.append("In KEV")
            cve.append(ransomwareUse[0])
    return cves 


def write_to_csv(cve_report: list, user_config: dict):
    
    print("\n***** Generating CSV report and writing to disk *****\n")
    
    now = datetime.now()
    date_time = now.strftime("%m-%d-%Y-%H-%M")
    file_path = user_config["USER_PROCESSED_VULNERABILITY_REPORT_DIR"]+date_time+"-"+user_config["USER_PROCESSED_VULNERABILITY_REPORT_BASE_NAME"]
    
    print(file_path)
    
    try:
        cve_df = pd.DataFrame(cve_report, columns=['cveID', 'vulnStatus', 'baseScore', 'baseSeverity', 'attackVector', 'accessComplexity', 'isKEV', 'knownRansomwareCampaignUse'])
        cve_df.to_excel(file_path)
    except Exception as e:
        print(f"Error processing file: {e}")
    else:
        print(f"Wrote file: {file_path}")


def enrich_vuldb(cve_data: list, baseSeverity: list = ["CRITICAL"]):
    
    cve_df = pd.DataFrame(cve_data, columns=['cveID', 'vulnStatus', 'baseScore', 'baseSeverity', 'attackVector', 'accessComplexity', 'isKEV', 'knownRansomwareCampaignUse', ])
    selected_cve_df = cve_df.loc[cve_df['baseSeverity'].isin(baseSeverity)]
    HEADER = {'X-VulDB-ApiKey': VULDB_API_KEY}
    
    for index, row in selected_cve_df.iterrows():
        cve = row["cveID"]
        vuldb_url = "https://vuldb.com/?api"
        cve_vuldb_search_data = {
            "search": cve,
            "details": "1"
        }

        try:
            response = requests.post(url = vuldb_url, headers = HEADER, data=cve_vuldb_search_data)
            response_json = json.loads(response.content)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            
            #* in a good call the top level keys are: response, request, result
            vuldb_response_keys = response_json["response"].keys()
 
            print(response_json["request"]["value"])
            print(response_json["result"][0]["entry"]["details"]["exploit"])

            vuldb_response_keys = response_json["response"].keys()

            if "error" in vuldb_response_keys:
                print("Your number of vuldb API calls for today has been exceeded")
            # if response_json["response"]["error"] == "API rate exceeded":
            #     print("Your number of vuldb API calls for today has been exceeded")
            # elif :
            #     vuldb_details_keys = response_json["result"][0]["entry"]["details"].keys()
            #     # print(vuldb_details_keys)
            #     vuldb_exploit_keys = response_json["result"][0]["exploit"].keys()
            #     print(vuldb_exploit_keys)
            #     if "exploit" in vuldb_details_keys:
            #         print("exploit ", response_json["result"])
            #         details_exploit = response_json["result"][0]["entry"]["details"]["exploit"]
            #     else:
            #         details_exploit = "No exploit data available in vuldb"
                
            #     if "exploitability" in vuldb_exploit_keys:
            #         print("exploitability ", response_json["result"])
            #         exploitability = response_json["result"][0]["exploit"]["exploitability"]
            #     else:
            #         exploitability = "No exploitability data in vuldb"


if __name__ == "__main__":
    start = time.time()
    
    app_config, user_config = cve_config_bootstrap()
    unique_cves  = extract_CVEs(app_config, user_config)
    download_KEV_file(app_config, user_config)
    download_EPSS_file(app_config, user_config)
    download_EXPLOITDB_file(app_config, user_config)
    download_NVD_files(app_config, user_config)
    NVD_sleep_timer = calculate_NVD_run_time(unique_cves)
    cve_data = load_CVE_from_NVD(app_config, user_config, unique_cves, NVD_sleep_timer)
    CISA_KEV_DataFrame = load_KEV_data(app_config)
    cve_report = build_KEV_report(CISA_KEV_DataFrame, cve_data)
    write_to_csv(cve_report, user_config)

    print(f"Total Processing Time: {round((time.time() - start)/60, 2)} minutes")
