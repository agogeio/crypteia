import json
import os
import pandas as pd
import requests
import sys
import time


NVD_API_KEY = os.environ.get("NVD_API_KEY")


def calculate_run_time(unique_cves: tuple):
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


def load_from_api(app_config: dict, unique_cves: tuple, nvd_sleep_timer: 6):
    """ Extracts data from the National Vulnerability Database """
    
    print("\n***** Using NVD API for CVE processing *****\n")
    
    cve_list = []
    counter = 1
    HEADER = {'apiKey': NVD_API_KEY}
    NVD_URL = app_config["download_URLs"]["NVD_API_BASE_URL"]
    
    print(f"NVD sleep timer is set to {nvd_sleep_timer} second(s) to account for API \n")
    
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
                cve_list.append([cve, "Invalid", "None", "None", "None", "None"])
            else:            
                vulnStatus = response_json["vulnerabilities"][0]['cve']['vulnStatus']
                if vulnStatus == "Rejected":
                    cve_list.append([cve, vulnStatus, "None", "None", "None", "None"])
                    
                elif vulnStatus != "Rejected":
                    cve_keys = response_json["vulnerabilities"][0]['cve']['metrics'].keys()
                    if "cvssMetricV31" in cve_keys:
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        attackVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
                        attackComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity])
                    elif "cvssMetricV30" in cve_keys:
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                        attackVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
                        attackComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity, attackVector, attackComplexity])
                    elif "cvssMetricV2" in cve_keys:
                        cvssData_keys = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'].keys()
                        if "baseSeverity" in cvssData_keys:
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                            accessVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
                            accessComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
                            cve_list.append([cve, vulnStatus, baseScore, baseSeverity, accessVector, accessComplexity])
                        elif "baseSeverity" not in cvssData_keys:
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            accessVector = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
                            accessComplexity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
                            cve_list.append([cve, vulnStatus, baseScore, "None", accessVector, accessComplexity])
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



def merge(app_config: dict):
    master_cve_list = []

    nvd_data_dir = app_config["NVD_DATA_DIR"]
    nvd_data_files = app_config["NVD_DATA_FILES"]
    nvd_master_file = app_config["NVD_FILE"] 
    
    
    for data_file in nvd_data_files:
        nvd_file_path = nvd_data_dir+data_file
        try:
            with open(nvd_file_path, encoding='utf-8') as nvd_file:
                nvd_data = nvd_file.read()
                nvd_json = json.loads(nvd_data)
        except Exception as e:
            print(f"File processing error: {e}")
        finally:
            # print(json.dumps(nvd_json["CVE_Items"], indent=4, sort_keys=True))
            nvd_cve_items = nvd_json["CVE_Items"]
            # print(type(nvd_cve_items))
            for nvd_cve in nvd_cve_items:
                master_cve_list.append(nvd_cve)
                # print(json.dumps(nvd_cve["cve"], indent=4, sort_keys=True))
                
    print(f"Number of CVE records: {len(master_cve_list)}")
    print(f"CVE list size in MB: {((sys.getsizeof(master_cve_list)/1024)/1024)}")
    # print(json.dumps(master_cve_list[0]["cve"], indent=4, sort_keys=True))
    
    cve_items_df = pd.DataFrame(master_cve_list)
    print(f"CVE DataFrame size in MB: {((sys.getsizeof(cve_items_df)/1024)/1024)}")
    
    try:
        nvd_master_file_path = nvd_data_dir+nvd_master_file
        cve_items_df.to_json(nvd_master_file_path)
    except Exception as e:
        print(f"Error writing nvd_master.json: {e}")
    finally:
        print(f"File {nvd_master_file} written to the filesystem")


if __name__ == "__main__":
    import config
    
    UNIQUE_CVES = ["CVE-2016-2183", "CVE-2023-23375", "CVE-2023-28304",  "CVE-2022-31777", "CVE-2023-4128", "CVE-2015-2808"]
    
    app_config, user_config = config.bootstrap()
    merge(app_config)
    # nvd_data = load_from_api(app_config, UNIQUE_CVES, 1)
    # print(nvd_data)
    
    