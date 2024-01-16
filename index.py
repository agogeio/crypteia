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

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_API_KEY = os.environ.get("NVD_API_KEY")
VULDB_API_KEY = os.environ.get("VULDB_API_KEY")

if NVD_API_KEY != "None":
    SLEEP_TIMER = .33
else:
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
            for cve in split_cve:
                cve_list.append(cve)
        cve_tuple = tuple(cve_list)
    
    number_of_cves = len(cve_tuple)
    
    if NVD_API_KEY != "None":
        time_to_process = number_of_cves / 100
    else:
        time_to_process = number_of_cves / 10
    
    print(f'{number_of_cves} unique CVEs processed, this process will take roughly {time_to_process} minutes to run due to NVD API rate limiting') 
    return cve_tuple


def load_CVE_from_NVD(cve_tuple: tuple):
    """ Extracts data from the National Vulnerability Database """
    cve_list = []
    HEADER = {'apiKey': NVD_API_KEY}
    
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
        except Exception as e:
            print(f'CVE Processing Error: {e}')
        finally:
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
            time.sleep(SLEEP_TIMER)
    return cve_list


def write_to_csv(cve_report: list, file_name: str):
    cve_df = pd.DataFrame(cve_report, columns=['cveID', 'vulnStatus', 'baseScore', 'baseSeverity', 'attackVector', 'accessComplexity', 'isKEV', 'knownRansomwareCampaignUse'])
    cve_df.to_excel(file_name)


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
            if response_json["response"]["error"] == "API rate exceeded":
                print("Your number of vuldb API calls for today has been exceeded")
            else:
                vuldb_details_keys = response_json["result"][0]["entry"]["details"].keys()
                # print(vuldb_details_keys)
                vuldb_exploit_keys = response_json["result"][0]["exploit"].keys()
                print(vuldb_exploit_keys)
                if "exploit" in vuldb_details_keys:
                    print("exploit ", response_json["result"][0]["entry"]["details"]["exploit"])
                    details_exploit = response_json["result"][0]["entry"]["details"]["exploit"]
                else:
                    details_exploit = "No exploit data available in vuldb"
                
                if "exploitability" in vuldb_exploit_keys:
                    print("exploitability ", response_json["result"][0]["exploit"]["exploitability"])
                    exploitability = response_json["result"][0]["exploit"]["exploitability"]
                else:
                    exploitability = "No exploitability data in vuldb"
        

if __name__ == "__main__":
    test_cveIDs = ("CVE-2021-27103", "CVE-2021-21017", "CVE-2017-0170", "CVE-2023-4128", "CVE-2015-2808", "CVE-2023-40481")

    print("\nWelcome to CVE Parse and Process, this program will take as an input\n",
          "a file containing vulnerabilities and process them against the NVD and\n",
          "CISA KEV database to identify what CVEs are being actively exploited and\n",
          "being used for ransomware attacks.  The limiting factor of this program's\n",
          "efficiency is the rate limit on the NVD API\n")
    
    start = time.time()
    validate_KEV_file()
    KEV_df = load_KEV_data()
    
    #? Real Data
    # CVEs = extract_CVEs(path='VulnerabilityReport.xlsx', sheet="CVE", column="CVE")
    # cve_data = load_CVE_from_NVD(CVEs)
    
    #! Test Data
    cve_data = load_CVE_from_NVD(test_cveIDs)
    
    cve_report = build_KEV_report(KEV_df=KEV_df, cveIDs=cve_data)
    enriched_cve_report = enrich_vuldb(cve_report, ["CRITICAL", "HIGH"])
    write_to_csv(cve_report, REPORT_NAME)

    print(f"Total Processing Time: {round((time.time() - start)/60, 2)} minutes")
