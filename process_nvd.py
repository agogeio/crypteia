import json
import pandas as pd
import os
import sys



nvd_master_json_file = ""


def process_nvd_files(app_config: dict):
    impact_list = []
    impact_tuple = ()
    cve_count = 0
    cve_rejected = 0
    cve_no_cvss = 0
    


    nvd_data_files = []
    nvd_data_dir = app_config["NVD_DATA_DIR"]
    
    for nvd_file in app_config["NVD_DATA_FILES"]:
        nvd_data_files.append(nvd_data_dir+nvd_file)
        

    print(nvd_data_files)
    
    for nvd_file in nvd_data_files:
        
        try:
            with open(nvd_file, encoding="utf-8") as nvd_data:
                nvd_json = json.load(nvd_data)
                                
                for cve_data in nvd_json["CVE_Items"]:
                    cve_count += 1
                    
                    cve_id = cve_data["cve"]["CVE_data_meta"]["ID"]
                    cve_assigner = cve_data["cve"]["CVE_data_meta"]["ASSIGNER"]
                    description = cve_data["cve"]["description"]["description_data"][0]["value"]
                    
                    # print(f"{cve_data["cve"]["CVE_data_meta"]["ID"]}\n")
                    # print(f"{cve_data["cve"]["CVE_data_meta"]["ASSIGNER"]}\n")
                    # print(f"{cve_data["cve"]["description"]["description_data"][0]["value"]}\n")
                    
                    try:
                        cvss_keys = cve_data["impact"].keys()
                        if "baseMetricV3" in cvss_keys:
                            # print(f"{cve_data["impact"]["baseMetricV3"]["cvssV3"]}\n")
                            cvss_v3_version = cve_data["impact"]["baseMetricV3"]["cvssV3"]["version"]
                            cvss_v3_vectorString = cve_data["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
                            cvss_v3_attackVector = cve_data["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
                            cvss_v3_attackComplexity = cve_data["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"]
                            cvss_v3_privilegesRequired = cve_data["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"]
                            cvss_v3_userInteraction = cve_data["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"]
                            cvss_v3_baseSeverity = cve_data["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                        elif "baseMetricV2" in cvss_keys:
                            # print(f"{cve_data["impact"]["baseMetricV2"]["cvssV2"]}\n")
                            cvss_v2_version = cve_data["impact"]["baseMetricV2"]["cvssV2"]["version"]
                            cvss_v2_vectorString = cve_data["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
                            cvss_v2_accessVector = cve_data["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
                            cvss_v2_accessComplexity = cve_data["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"]
                            cvss_v2_authentication = cve_data["impact"]["baseMetricV2"]["cvssV2"]["authentication"]
                            cvss_v2_userInteraction = "None"
                            cvss_v2_baseScore = cve_data["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                        elif len(cvss_keys) == 0:
                            if "Rejected" in description:
                                # print(f"Rejected: {cve_id}")
                                cve_rejected += 1
                            elif "Rejected" not in description:
                            # print(f"No CVSS data for CVE: {cve_id} in file {nvd_path}")
                                # print(f"AWAITING ANALYSIS: {cve_id} - {nvd_path}")
                                cve_no_cvss += 1
                            else:
                                print("Unknown Status, Terminating")
                                sys.exit()
                        else:
                            print(cve_id)
                            print(nvd_file)
                            sys.exit()
                    except Exception as e:
                        print(e)
                    finally:
                        pass
                    
                    
                    # cvss_keys = cve_data["impact"].keys()
                    # if "baseMetricV3" in cvss_keys:
                    #     print(f"{cve_data["impact"]["baseMetricV3"]["cvssV3"]}\n")
                    # elif "baseMetricV2" in cvss_keys:
                    #     print(f"{cve_data["impact"]["baseMetricV2"]["cvssV2"]}\n")
                    # else:
                    #     print(f"{id}")
                    #     exit()
                        
                    #! print(f"{cve_data["cve"]["references"]["reference_data"]}\n")
                    # print(f"{cve_data["configurations"]}\n")
                    # print(f"{cve_data["publishedDate"]}\n")
                    # print(f"{cve_data["lastModifiedDate"]}\n")
                    
        
        except Exception as e:
            print(f"***** Error was: {e} *****")
        finally:
            pass
    
    print("")
    print(f"CVE Count: {cve_count}")
    print(f"CVEs with no CVSS: {cve_no_cvss}")
    print(f"Percentage of CVEs without CVSS {(cve_no_cvss/cve_count)}")
    print(f"Number of rejected CVEs: {cve_rejected}")
    
    
    
    impact_tuple = tuple(impact_list)
    print(f"Impact Tuple: \n{impact_tuple}")
