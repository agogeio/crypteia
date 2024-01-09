import os
import pandas as pd

from os.path import exists
from urllib.request import urlretrieve

KEV_FILENAME = 'known_exploited_vulnerabilities.json'
API_KEY = os.environ.get("nvd_key")

cve_list = []
cve_tuple = ()
vuln_medium = ()
vuln_high = ()
vuln_critical = ()

def get_KEV_filename():
    return 'known_exploited_vulnerabilities.json'


def get_KEV():
    url = ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    filename='known_exploited_vulnerabilities.json'

    try:
        urlretrieve(url=url, filename=filename)
    except Exception as e:
        print("The following error ocurred: ", e )
    finally:
        print("CISA KEV List downloaded")


def get_CVEs(path: str = 'VulnerabilityReport.xlsx', sheet: str = 'CVE', column: str = 'CVE'):

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
    
    print(f'{len(cve_tuple)} unique CVEs returned')    
    return cve_tuple
    

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


def rank_CVEs(cve_tuple: tuple):
    pass

    

if __name__ == "__main__":
    print("Welcome to CVE Parse")
    
    update_KEV()
    CVEs = get_CVEs(path='VulnerabilityReport.xlsx', sheet="CVE", column="CVE")
    rank_CVEs(CVEs)

