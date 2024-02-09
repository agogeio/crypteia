import json
import sys

import pandas as pd

def create_dataframe(app_config: dict):
    """ Returns the KEV dataset as a pd.Dataframe """
    
    print("\n***** Using local CISA KEV file to load into DataFrame *****\n")
    
    KEV_filename = app_config["CISA_KEV_DIR"]+app_config["CISA_KEV_FILE"]
    
    try:
        with open(KEV_filename) as KEV_file:
            KEV_data = KEV_file.read()
    except Exception as e:
        sys.exit(f'Error loading KEV File: {e}')
    else:
        KEV_json = json.loads(KEV_data)
        KEV_df =  pd.DataFrame.from_dict(KEV_json["vulnerabilities"])
        print(f"Loaded the following file into DataFrame with success: {KEV_filename}")
        
    return KEV_df


def build_report(KEV_df: pd.DataFrame, cve_data: list):  
    
    print("\n***** Enhancing report data with CISA KEV data *****\n")
    
    cves = cve_data      
    for cve in cves:
        result = KEV_df.loc[KEV_df["cveID"] == cve[0]]
        if len(result.values) == 0:
            cve.append("Not in KEV")
            cve.append("Not in KEV")
        else:
            ransomwareUse = result["knownRansomwareCampaignUse"].values
            cve.append("In KEV")
            cve.append(ransomwareUse[0])
    
    print("KEV data processing complete")        
    
    return cves


if __name__ == "__main__":
    import config
    
    nvd_data = [['CVE-2016-2183', 'Modified', 7.5, 'HIGH', 'NETWORK', 'LOW'], 
                ['CVE-2023-23375', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
                ['CVE-2023-28304', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
                ['CVE-2022-31777', 'Analyzed', 5.4, 'MEDIUM', 'NETWORK', 'LOW'], 
                ['CVE-2023-4128', 'Rejected', 'None', 'None', 'None', 'None'], 
                ['CVE-2015-2808', 'Modified', 5.0, 'None', 'NETWORK', 'LOW']]
    
    app_config, user_config = config.bootstrap()
    kev_df = create_dataframe(app_config)
    report = build_report(kev_df, nvd_data)
    
    print(f'KEV Report:\n{report}')