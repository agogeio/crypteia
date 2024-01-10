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

cve_list = []
cve_tuple = ()
vuln_medium = ()
vuln_high = ()
vuln_critical = ()

def load_KEV_data(cve: str = "CVE-2021-21017"):
    
    try:
        with open(KEV_FILENAME) as KEV_file:
            KEV_data = KEV_file.read()
            KEV_json = json.loads(KEV_data)
    except Exception as e:
        print(f'Error loading KEV File: {e}')
    finally:
        KEV_df =  pd.DataFrame.from_dict(KEV_json["vulnerabilities"])
        result = KEV_df.loc[KEV_df["cveID"] == cve]
        ransomwareUse = result["knownRansomwareCampaignUse"].values
        print(f'Ransomware: {ransomwareUse}')
        return ransomwareUse


def get_KEV():
    url = ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    filename='known_exploited_vulnerabilities.json'

    try:
        urlretrieve(url=url, filename=filename)
    except Exception as e:
        print("The following error ocurred: ", e )
    finally:
        print("CISA KEV List downloaded")


def update_KEV():
    if exists(KEV_FILENAME):
        print("The 'known_exploited_vulnerabilities.json' exists on the system")
    else:
        print("File does not exist")
        update = input("CISA KEV file does not exist, download it now (y/n): ")
        if update == 'y':
            get_KEV()
        else:
            print('The KEV JSON file has not been downloaded')
            

def extract_CVEs(path: str = 'VulnerabilityReport.xlsx', sheet: str = 'CVE', column: str = 'CVE'):

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
    
    print(f'{len(cve_tuple)} unique CVEs processed')    
    return cve_tuple


def get_CVE_data(cve_tuple: tuple):
    
    # response
    
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
            vulnStatus = response_json["vulnerabilities"][0]['cve']['vulnStatus']
            descriptions_value = response_json["vulnerabilities"][0]['cve']['descriptions'][0]['value']

            if vulnStatus == "Rejected":
                print(f'{cve} was {vulnStatus} by NVD with a description of: {descriptions_value}')
                
            elif vulnStatus != "Rejected":
                cve_keys = response_json["vulnerabilities"][0]['cve']['metrics'].keys()
                if "cvssMetricV31" in cve_keys:
                    # print(f'{cve} has cvssMetricV31')
                    baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                elif "cvssMetricV30" in cve_keys:
                    # print(f'{cve} has cvssMetricV30')
                    baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                    baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                    print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                elif "cvssMetricV2" in cve_keys:
                    # print(f'{cve} has cvssMetricV2')
                    cvssData_keys = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'].keys()
                    if "baseSeverity" in cvssData_keys:
                        # print('Sev')
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                        baseSeverity = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                        print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
                    elif "baseSeverity" not in cvssData_keys:
                        # print('No Sev')
                        baseScore = response_json["vulnerabilities"][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                        print(f'{cve:} has a base score of [{baseScore}]')
                else:
                    print('Unknown CVSS standard')
                    
            # print(f'{cve:} has a base score of [{baseScore}] and a base severity of !{baseSeverity}!')
            
        time.sleep(SLEEP_TIMER)


if __name__ == "__main__":
    print("Welcome to CVE Parse")
    
    update_KEV()
    load_KEV_data()
    CVEs = extract_CVEs(path='VulnerabilityReport.xlsx', sheet="CVE", column="CVE")
    get_CVE_data(CVEs)

