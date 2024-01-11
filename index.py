import datetime
import json
import os
import pandas as pd
import requests
import time

from os.path import exists
from urllib.request import urlretrieve

KEV_FILENAME = 'known_exploited_vulnerabilities.json'
#! The public rate limit (without an API key) is 5 requests in a rolling 30 second window; 
#! the rate limit with an API key is 50 requests in a rolling 30 second window. 
API_KEY = os.environ.get("nvd_key")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
SLEEP_TIMER = 6
REPORT_NAME = "processed_vulnerability_report.xlsx"

cve_list = []
cve_tuple = ()
vuln_medium = ()
vuln_high = ()
vuln_critical = ()


def build_KEV_report(KEV_df: pd.DataFrame, cveIDs: list):  
    cves = cveIDs      
        
    for cve in cves:
        result = KEV_df.loc[KEV_df["cveID"] == cve[0]]
        # print(cve)
        
        if len(result.values) == 0:
            cve.append("No")
            cve.append("N/A")
            # print("No KEV results")
        else:
            ransomwareUse = result["knownRansomwareCampaignUse"].values
            # print(f'Ransomware: {ransomwareUse[0]}')
            cve.append("Yes")
            cve.append(ransomwareUse[0])

    return cves


def download_KEV_file():
    """ Downloads the KEV JSON file """
    url = ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    filename='known_exploited_vulnerabilities.json'

    try:
        urlretrieve(url=url, filename=filename)
    except Exception as e:
        print("The following error ocurred: ", e )
    finally:
        print("CISA KEV List downloaded")

 
def load_KEV_data(cve: str = "CVE-2021-21017"):
    """ Returns the KEV dataset as a pd.Dataframe """
    try:
        with open(KEV_FILENAME) as KEV_file:
            KEV_data = KEV_file.read()
            KEV_json = json.loads(KEV_data)
    except Exception as e:
        print(f'Error loading KEV File: {e}')
        return e
    finally:
        KEV_df =  pd.DataFrame.from_dict(KEV_json["vulnerabilities"])
        return KEV_df


def validate_KEV_file():
    """ Checks to see if the KEV JSON file exists and will call get_KEV() if required """
    if exists(KEV_FILENAME):
        print("The 'known_exploited_vulnerabilities.json' exists on the system\n")
    else:
        print("File does not exist")
        update = input("CISA KEV file does not exist, download it now (y/n): ")
        if update == 'y':
            download_KEV_file()
        else:
            print('The KEV JSON file has not been downloaded')


def extract_CVEs(path: str = 'VulnerabilityReport.xlsx', sheet: str = 'CVE', column: str = 'CVE'):
    """ Extracts CVEs from provided report, returns data as tuple """
    cols = [column]
    try:
        df = pd.read_excel(path, sheet_name=sheet, usecols=cols)
        #! df.dropna() will drop the NaN from the specified column
        df = df.dropna(subset=cols[0])
    except Exception as e:
        print("There was an error:", e)
    finally:
        np_cve = pd.DataFrame(df[column].unique())
       
        for cve_collection in np_cve[0]:
            split_cve = cve_collection.split(',')
            # print(split_cve)
            
            for cve in split_cve:
                # print(cve)
                cve_list.append(cve)
                
        cve_tuple = tuple(cve_list)
    
    number_of_cves = len(cve_tuple)
    time_to_process = number_of_cves / 10
    
    print(f'{number_of_cves} unique CVEs processed, this process will take roughly {time_to_process} minutes to run due to NVD API rate limiting') 
    print(f'Processing start time begins at: {datetime.datetime.now()}\n')
    return cve_tuple


def load_CVE_from_NVD(cve_tuple: tuple):
    """ Extracts data from the National Vulnerability Database """
    cve_list = []
    
    for cve in cve_tuple:
        total_url = NVD_URL+cve      
        print(f'Processing CVE id: {cve} with URL of: {total_url}')
        
        #! Modified CVE
        # total_url = NVD_URL+'CVE-2017-0170' 
        #! https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-0170
        
        #! Rejected CVE
        # total_url = NVD_URL+'CVE-2023-4128' 
        #! https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-4128
        
        #! No baseSeverity
        #! https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-2808
        # total_url = NVD_URL+'CVE-2015-2808' 
        
        baseScore = ""
        baseSeverity = ""
        
        try:
            response = requests.get(total_url)
            response_json = response.json()
        except Exception as e:
            print(f'CVE Processing Error: {e}')
        finally:
            
            if response_json["totalResults"] == 0:
                cve_list.append([cve, "Invalid", "N/A", "N/A"])
            else:            
                vulnStatus = response_json["vulnerabilities"][0]['cve']['vulnStatus']
                descriptions_value = response_json["vulnerabilities"][0]['cve']['descriptions'][0]['value']

                if vulnStatus == "Rejected":
                    # print(f'{cve} was {vulnStatus} by NVD with a description of: {descriptions_value}')
                    cve_list.append([cve, vulnStatus, "N/A", "N/A"])
                    
                elif vulnStatus != "Rejected":
                    cve_keys = response_json["vulnerabilities"][0]['cve']['metrics'].keys()
                    if "cvssMetricV31" in cve_keys:
                        # print(f'{cve} has cvssMetricV31')
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity])
                    elif "cvssMetricV30" in cve_keys:
                        # print(f'{cve} has cvssMetricV30')
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                        # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                        cve_list.append([cve, vulnStatus, baseScore, baseSeverity])
                    elif "cvssMetricV2" in cve_keys:
                        # print(f'{cve} has cvssMetricV2')
                        cvssData_keys = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'].keys()
                        if "baseSeverity" in cvssData_keys:
                            # print('Sev')
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                            # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                            cve_list.append([cve, vulnStatus, baseScore, baseSeverity])
                        elif "baseSeverity" not in cvssData_keys:
                            # print('No Sev')
                            baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                            # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !N/A!')
                            cve_list.append([cve, vulnStatus, baseScore, "N/A"])
                    else:
                        print('Unknown CVSS standard')
                
            time.sleep(SLEEP_TIMER)
        
    return cve_list


def write_to_csv(cve_report: list):
    cve_df = pd.DataFrame(cve_report, columns=['cveID', 'vulnStatus', 'baseScore', 'baseSeverity', 'isKEV', 'knownRansomwareCampaignUse'])
    # print(cve_df)
    cve_df.to_excel(REPORT_NAME)
    

if __name__ == "__main__":
    test_cveIDs = ("CVE-2021-27103", "CVE-2021-21017", "CVE-2017-0170", "CVE-2023-4128", "CVE-2015-2808", "CVE-2023-40481")

    print("Welcome to CVE Parse and Process, this program will take as an input\n",
          "a file containing vulnerabilities and process them against the NVD and\n",
          "CISA KEV database to identify what CVEs are being actively exploited and\n",
          "being used for ransomware attacks.  The limiting factor of this program's\n",
          "efficiency is the rate limit on the NVD API\n")
    
    
    validate_KEV_file()
    KEV_df = load_KEV_data()
    CVEs = extract_CVEs(path='VulnerabilityReport.xlsx', sheet="CVE", column="CVE")
    # cve_data = load_CVE_from_NVD(test_cveIDs)
    cve_data = load_CVE_from_NVD(CVEs)
    cve_report = build_KEV_report(KEV_df=KEV_df, cveIDs=cve_data)
    write_to_csv(cve_report)
