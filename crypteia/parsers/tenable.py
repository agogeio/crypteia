import pandas as pd
import sys

def tenable(vuln_file):
    """ Extracts CVEs from provided report, returns data as tuple """
    
    print("\n***** Beginning processing of user supplied Tenable vulnerability file *****\n")
 
    USER_VULNERABILITY_SHEET_NAME = "CVE"
    USER_VULNERABILITY_COLUMN_NAME = "CVE"
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    cve_list = []
    
    try:
        print(f"Processing report: {vuln_file}")
        df = pd.read_excel(vuln_file, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=cols)
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
        
    return cve_tuple