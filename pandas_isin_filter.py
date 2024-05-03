import pandas as pd
    
# cols = ["ID", "Location" , "Availability", "Sale"]
# data = [[1, "Michigan", "In Stock", False],
#         [2, "Ohio", "In Stock", False],
#         [3, "Texas", "Unavailable", True],
#         [4, "Michigan", "Unavailable", True],
#         [5, "Alaska", "In Stock", False]]    


# state_filter = ["Michigan"]
# availability_filter = ["In Stock"]
# sale_filter = [True]
    
# inventory = pd.DataFrame(data=data, columns=cols)

# filtered_inventory = inventory[
#     (inventory["Location"].isin(state_filter)) 
#     | (inventory["Availability"].isin(availability_filter)) 
#     | (inventory["Sale"].isin(sale_filter))]

# # print(inventory)
# print(filtered_inventory)

vuln_report = pd.read_excel("./export/sample.xlsx")
av = ["NETWORK", "ADJACENT_NETWORK"]
kev = ["In KEV"]
ransomware = ["Unknown"]

print("Unfiltered Report:")
print(vuln_report[["attackVector", "isKEV", "knownRansomwareCampaignUse"]], len(vuln_report))

filtered_vuln_report = vuln_report[
    (vuln_report["attackVector"].isin(av)) 
    | (vuln_report["isKEV"].isin(kev)) 
    | (vuln_report["knownRansomwareCampaignUse"].isin(ransomware))]

# filtered_vuln_report = vuln_report[
#     (vuln_report["isKEV"].isin(kev)) 
#     | (vuln_report["knownRansomwareCampaignUse"].isin(ransomware))]

print("Filtered Report:")
print(filtered_vuln_report[["attackVector", "isKEV", "knownRansomwareCampaignUse"]], len(filtered_vuln_report))