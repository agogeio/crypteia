import os 
import pandas as pd
import re
import sys

def extract(vendor: str, vuln_file):
    vendor = vendor
    
    if vendor == 'Tenable':
        unique_cves = tenable(vuln_file)
        return unique_cves
    if vendor == "Rapid7":
        unique_cves = rapid7(vuln_file)
        return unique_cves


def rapid7(vuln_file):
    """ Extracts CVEs from provided report, returns data as tuple """
    
    print("\n***** Beginning processing of user supplied Rapid7 vulnerability file *****\n")

    USER_VULNERABILITY_SHEET_NAME = "CVE"
    USER_VULNERABILITY_COLUMN_NAME = "CVE"
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    cve_list = []
    cve_tuple = ()
    
    # vulnerability_report_path = USER_VULNERABILITY_IMPORT_REPORT_DIR+USER_VULNERABILITY_IMPORT_REPORT_NAME

    try:
        print(f"Processing report: {vuln_file}")
        df = pd.read_excel(vuln_file, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=[USER_VULNERABILITY_COLUMN_NAME])
        #! df.dropna() will drop the NaN from the specified column
        df = df.dropna(subset=cols[0])
        np_cve = pd.DataFrame(df[USER_VULNERABILITY_COLUMN_NAME].unique())
    except Exception as e:
        sys.exit("There was an error:", e)
    else:
        for cve_collection in np_cve[0]:
            matches = re.search(r"CVE-\d{4}-\d{4,7}", cve_collection)
            if matches:
                cve_list.append(matches.group())

    cve_tuple = tuple(cve_list)
    print(f"Successfully created DataFrame from {vuln_file}")
        
    # s = pd.Series(cve_tuple)
    # cve_dataframe = pd.DataFrame(s, columns=['cveID'])
    return cve_tuple
            

def tenable(vuln_file):
    """ Extracts CVEs from provided report, returns data as tuple """
    
    print("\n***** Beginning processing of user supplied Tenable vulnerability file *****\n")
 
    USER_VULNERABILITY_SHEET_NAME = "CVE"
    USER_VULNERABILITY_COLUMN_NAME = "CVE"
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    cve_list = []
    
    # vulnerability_report_path = USER_VULNERABILITY_IMPORT_REPORT_DIR+USER_VULNERABILITY_IMPORT_REPORT_NAME

    try:
        print(f"Processing report: {vuln_file}")
        df = pd.read_excel(vuln_file, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=cols)
        #! df.dropna() will drop the NaN from the specified column
        df = df.dropna(subset=cols[0])
        np_cve = pd.DataFrame(df[USER_VULNERABILITY_COLUMN_NAME].unique())
    except Exception as e:
        sys.exit(f"There was an error: {e}")
    else:
        for cve_collection in np_cve[0]:
            split_cve = cve_collection.split(',')
            for cve in split_cve:
                cve_list.append(cve)
        cve_tuple = tuple(cve_list)
        print(f"Successfully created DataFrame from {vuln_file}")
        
    # s = pd.Series(cve_tuple)
    # cve_dataframe = pd.DataFrame(s, columns=['cveID'])
    return cve_tuple
    

if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    unique_cves = extract(app_config, user_config)
    print(unique_cves)