import os 
import pandas as pd
import sys


def extract(app_config: dict, user_config: dict):
    vendor = user_config["USER_VULNERABILITY_SCAN_VENDOR"]
    
    if vendor == 'T':
        unique_cves = tenable(app_config, user_config)
        return unique_cves
    if vendor == "R":
        unique_cves = rapid7(app_config, user_config)
        return unique_cves
 
 
def rapid7(app_config: dict, user_config: dict):
    """ Extracts CVEs from provided report, returns data as tuple """
    
    print("\n***** Beginning processing of user supplied Rapid7 vulnerability file *****\n")
 
    USER_VULNERABILITY_IMPORT_REPORT_DIR = user_config["USER_VULNERABILITY_IMPORT_REPORT_DIR"]
    USER_VULNERABILITY_IMPORT_REPORT_NAME = user_config["USER_VULNERABILITY_IMPORT_REPORT_NAME"]
    USER_VULNERABILITY_SHEET_NAME = user_config["USER_VULNERABILITY_SHEET_NAME"]
    USER_VULNERABILITY_COLUMN_NAME = user_config["USER_VULNERABILITY_COLUMN_NAME"]
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    cve_list = []
    cve_tuple = ()
    
    vulnerability_report_path = USER_VULNERABILITY_IMPORT_REPORT_DIR+USER_VULNERABILITY_IMPORT_REPORT_NAME
    
    
    if not os.path.exists(USER_VULNERABILITY_IMPORT_REPORT_DIR):
        sys.exit(f'''There is no {USER_VULNERABILITY_IMPORT_REPORT_DIR} directory, please create it and place the vulnerability report named {USER_VULNERABILITY_IMPORT_REPORT_NAME} in the directory.  Terminating program.''')
        
    else:
        try:
            print(f"Processing report: {vulnerability_report_path}")
            df = pd.read_excel(vulnerability_report_path, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=[USER_VULNERABILITY_COLUMN_NAME])
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
        print(f"Successfully created DataFrame from {vulnerability_report_path}")
            
        return cve_tuple
            

def tenable(app_config: dict, user_config: dict):
    """ Extracts CVEs from provided report, returns data as tuple """
    
    print("\n***** Beginning processing of user supplied Tenable vulnerability file *****\n")
 
    USER_VULNERABILITY_IMPORT_REPORT_DIR = user_config["USER_VULNERABILITY_IMPORT_REPORT_DIR"]
    USER_VULNERABILITY_IMPORT_REPORT_NAME = user_config["USER_VULNERABILITY_IMPORT_REPORT_NAME"]
    USER_VULNERABILITY_SHEET_NAME = user_config["USER_VULNERABILITY_SHEET_NAME"]
    USER_VULNERABILITY_COLUMN_NAME = user_config["USER_VULNERABILITY_COLUMN_NAME"]
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    cve_list = []
    
    vulnerability_report_path = USER_VULNERABILITY_IMPORT_REPORT_DIR+USER_VULNERABILITY_IMPORT_REPORT_NAME
    
    
    if not os.path.exists(USER_VULNERABILITY_IMPORT_REPORT_DIR):
        sys.exit(f'''There is no {USER_VULNERABILITY_IMPORT_REPORT_DIR} directory, please create it and place the vulnerability report named {USER_VULNERABILITY_IMPORT_REPORT_NAME} in the directory.  Terminating program.''')
        
    else:
        try:
            print(f"Processing report: {vulnerability_report_path}")
            df = pd.read_excel(vulnerability_report_path, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=cols)
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
            print(f"Successfully created DataFrame from {vulnerability_report_path} ")
            
        return cve_tuple
    

if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    unique_cves = extract(app_config, user_config)
    print(unique_cves)