from datetime import datetime
import pandas as pd
import sys

columns=['cveID', 'vulnStatus', 'baseScore', 'baseSeverity', 'attackVector', 'accessComplexity', 'vectorString', 'isKEV', 'knownRansomwareCampaignUse']

def csv(user_config: dict, cve_report: list):
    
    print("\n***** Generating CSV report and writing to disk *****\n")
    
    now = datetime.now()
    date_time = now.strftime("%m-%d-%Y-%H-%M")
    file_path = user_config["USER_PROCESSED_VULNERABILITY_REPORT_DIR"]+date_time+"-"+user_config["USER_PROCESSED_VULNERABILITY_REPORT_BASE_NAME"]+".csv"
    
    try:
        cve_df = pd.DataFrame(cve_report, columns=columns)
        cve_df.to_csv(file_path)
    except Exception as e:
        sys.exit(f"Error in write report processing CSV file: {e}")
    else:
        print(f"Wrote processed report to file: {file_path}")
        
    return file_path


def excel(user_config: dict, cve_report: list):
    
    print("\n***** Generating CSV report and writing to disk *****\n")
    
    now = datetime.now()
    date_time = now.strftime("%m-%d-%Y-%H-%M")
    file_path = user_config["USER_PROCESSED_VULNERABILITY_REPORT_DIR"]+date_time+"-"+user_config["USER_PROCESSED_VULNERABILITY_REPORT_BASE_NAME"]+".xlsx"
    
    try:
        cve_df = pd.DataFrame(cve_report, columns=columns)
        cve_df.to_excel(file_path)
    except Exception as e:
        sys.exit(f"Error in write report processing Excel file: {e}")
    else:
        print(f"Wrote processed report to file: {file_path}")
        
    return file_path


if __name__ == "__main__":
    import config
    
    report = [['CVE-2016-2183', 'Modified', 7.5, 'HIGH', 'NETWORK', 'LOW', 'Sample Vector' ,'Not in KEV', 'Not in KEV'], 
              ['CVE-2023-23375', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW', 'Sample Vector' , 'Not in KEV', 'Not in KEV'], 
              ['CVE-2023-28304', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW', 'Sample Vector' , 'Not in KEV', 'Not in KEV'], 
              ['CVE-2022-31777', 'Analyzed', 5.4, 'MEDIUM', 'NETWORK', 'Sample Vector' , 'LOW', 'Not in KEV', 'Not in KEV'], 
              ['CVE-2023-4128', 'Rejected', 'None', 'None', 'None', 'None', 'Sample Vector', 'Not in KEV', 'Not in KEV'], 
              ['CVE-2015-2808', 'Modified', 5.0, 'None', 'NETWORK', 'LOW', 'Sample Vector', 'Not in KEV', 'Not in KEV']]
    
    _, user_config = config.bootstrap()
    
    csv(user_config, report)
    excel(user_config, report)