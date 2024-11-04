import pandas as pd
import re
import sys

def rapid7(vuln_file):
    """ Extracts CVEs from provided report, returns data as tuple """
    
    print("\n***** Beginning processing of user supplied Rapid7 vulnerability file *****\n")

    USER_VULNERABILITY_SHEET_NAME = "CVE"
    USER_VULNERABILITY_COLUMN_NAME = "CVE"
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    cve_list = []
    cve_tuple = ()
    
    try:
        print(f"Processing report: {vuln_file}")
        df = pd.read_excel(vuln_file, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=[USER_VULNERABILITY_COLUMN_NAME])
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
    return cve_tuple