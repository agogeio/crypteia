import csv

import pandas as pd

from cve_parse import utils

THREAT_INTEL_TYPE = 'SEARCHSPLOIT'

STATUS_ERROR = 400
STATUS_TERMINATE = 500
STATUS_OK = 200


# To fully access the SearchSploit data you need to use the functions in the following order:
# 1. download()
# 2. transform()
# 3. load()
# 4. search()


def download(app_config: dict, user_config: dict) -> dict:
    """
    Downloads the SearchSploit dataset from their GitLab repo at https://gitlab.com/exploit-database/exploitdb
    If AUTO_DOWNLOAD_ALL and DATA_AUTO_UPDATE are both set to false, you can end up 
    with a situation where files are missing and the program must terminate.

    Args:
        app_config (dict):  To access config data in the app_config.json file
        user_config (dict): To access config data in the user_config.json file

    Returns:
        dict: with keys: error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """

    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    SEARCHSPLOIT_DATA_AUTO_UPDATE = user_config["SEARCHSPLOIT_DATA_AUTO_UPDATE"]

    SEARCHSPLOIT_DOWNLOAD_URL = app_config["download_URLs"]["SEARCHSPLOIT_DOWNLOAD_URL"]
    SEARCHSPLOIT_DIR = app_config["SEARCHSPLOIT_DIR"]
    SEARCHSPLOIT_CSV_FILE = app_config["SEARCHSPLOIT_CSV_FILE"]
    
    SEARCHSPLOIT_PATH=SEARCHSPLOIT_DIR+SEARCHSPLOIT_CSV_FILE
    
    status = STATUS_OK
    message = ""
    
    #* Checks if the directory exists and will try and create it
    response = utils.directory_manager(SEARCHSPLOIT_DIR)
    if "error" in response.keys():
        message = response["error"]
    elif "error" not in response.keys():
        message = response["message"]
    else:
        status = STATUS_TERMINATE
        message = response["message"]
        return {"message" : message, "status" : status}
 
    #* Checks file age and config settings to see if files should be downloaded
    response = utils.file_manager(AUTO_DOWNLOAD_ALL, SEARCHSPLOIT_DATA_AUTO_UPDATE, SEARCHSPLOIT_PATH)
    if "error" in response.keys():
        message = response["error"]
    elif "error" not in response.keys():
        if response['action'] == 'download':
            response = utils.file_download(SEARCHSPLOIT_DOWNLOAD_URL, SEARCHSPLOIT_PATH)
            message = response["message"]
        elif response['action'] == 'none':
            message = response["message"]
    else:
        status = STATUS_TERMINATE
        message = response["message"]
        return {"message" : message, "status" : status}

    return {"message" : message, "status" : status}


def load(app_config: dict) -> dict:
    """
    Loads the SearchSploit data from an Excel file on disk into a DataFrame

    Args:
        app_config (dict):  To access config data in the app_config.json file

    Returns:
        dict: with keys: data with the SearchSploit DataFrame, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    SEARCHSPLOIT_DIR = app_config["SEARCHSPLOIT_DIR"]
    SEARCHSPLOIT_EXCEL_FILE = app_config["SEARCHSPLOIT_EXCEL_FILE"]
    SEARCHSPLOIT_EXCEL_PATH = SEARCHSPLOIT_DIR+SEARCHSPLOIT_EXCEL_FILE

    error = ""
    message = ""
    status = STATUS_OK

    try:
        searchsploit_df = pd.read_excel(SEARCHSPLOIT_EXCEL_PATH)
    except Exception as e:
        error = f"Unable to load {SEARCHSPLOIT_EXCEL_PATH} with error: {e}"
        message = f"Unable to load {SEARCHSPLOIT_EXCEL_PATH} in DataFrame"
        status = STATUS_ERROR
        return {"error": error, "message": message , "status": status}
    else:
        message = f"Loaded DataFrame with data from {SEARCHSPLOIT_EXCEL_PATH}"
        return {"data": searchsploit_df, "message": message , "status": status}


def search(searchsploit_df: pd.DataFrame, unique_cves: list) -> dict:
    """
    Searches the SearchSploit data in the provided DataFrame for CVEs held in the list.

    Args:
        searchsploit_df (pd.DataFrame): Accepts a dataframe with SearchSploit data
        unique_cves (list): Accepts a list of CVE values

    Returns:
        dict: with keys: data, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
        return data is an list of dicts with structure 
        {
            "isSearchSploit": Yes or No,
            "description": value or N/A,
            "type": value or N/A,
            "platform": value or N/A,
            "codes": value(s) of list of related CVEs or N/A"
        }
    """
    
    #* .sort() is an in place method
    unique_cves.sort()
    
    columns = ['isSearchSploit', 'description', 'type', 'platform', 'codes']
    searchsploit_record = {}
    data = []
    
    try:
        for cve in unique_cves:
            filtered_df = searchsploit_df[searchsploit_df["codes"].str.contains(cve, case=False)]

            if len(filtered_df) == 0:
                
                searchsploit_record = {
                    "isSearchSploit" : "No",
                    "description" : "N/A",
                    "type" : "N/A",
                    "platform" : "N/A",
                    "codes" : "N/A"
                }
                data.append(searchsploit_record)
                
            elif len(filtered_df) > 0:
                
                searchsploit_record = {
                    "isSearchSploit" : "Yes",
                    "description" : filtered_df.iloc[0]['description'],
                    "type" : filtered_df.iloc[0]['type'],
                    "platform" : filtered_df.iloc[0]['platform'],
                    "codes" : filtered_df.iloc[0]['codes']
                }
                data.append(searchsploit_record)
            
    except Exception as e:
        return {"error": e, "message" : f"SearchSploit query error: {e}", "status" : STATUS_ERROR}
    else:
        return {"data": data, "columns" : columns, "message" : f"SearchSploit query complete", "status" : STATUS_OK}


def transform(app_config: dict) -> dict:
    """
    Transforms the SearchSploit dataset and converts it into an Excel file with usable data

    Args:
        app_config (dict): Accepts the app_config for file location information 

    Returns:
        dict: with keys: action, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    SEARCHSPLOIT_DIR = app_config["SEARCHSPLOIT_DIR"]
    SEARCHSPLOIT_CSV_FILE = app_config["SEARCHSPLOIT_CSV_FILE"]
    SEARCHSPLOIT_EXCEL_FILE = app_config["SEARCHSPLOIT_EXCEL_FILE"]
    
    SEARCHSPLOIT_CSV_PATH = SEARCHSPLOIT_DIR+SEARCHSPLOIT_CSV_FILE
    SEARCHSPLOIT_EXCEL_PATH = SEARCHSPLOIT_DIR+SEARCHSPLOIT_EXCEL_FILE
    
    clean_string = ""
    column_headers = ["description", "type", "platform", "codes"]
    error = ""
    message = ""
    status = STATUS_OK
    transformed = []

    try:
        with open(SEARCHSPLOIT_CSV_PATH, mode='r', encoding='utf-8') as searchsploit_file:
            reader = csv.reader(searchsploit_file)
            searchsploit = [row for row in reader]
        try:
            for item in searchsploit:
                codes = item[11]
                split = codes.split(';')
                for element in split:
                    if "CVE-" in element and clean_string ==  "":
                        clean_string = f"{element}"
                    elif "CVE-" in element:
                        clean_string = f"{clean_string},{element}"
                    elif "CVE-" not in element:
                        clean_string = clean_string+""

                item[11] = clean_string
                clean_string = ""
        except Exception as e:
            status = STATUS_ERROR
            return {"error": e, "status": status}
    except Exception as e:
            status = STATUS_ERROR
            return {"error": e, "status": status}
            
    for row in searchsploit:
        entry=[row[2],row[5],row[6],row[11]]
        transformed.append(entry)
        
    del transformed[0]
    
    searchsploit_df = pd.DataFrame(transformed, columns=column_headers)
    searchsploit_df.dropna(subset=["codes"], inplace=True)
    
    searchsploit_df = searchsploit_df[searchsploit_df["codes"] != ""]
    
    try:
        searchsploit_df.to_excel(SEARCHSPLOIT_EXCEL_PATH, index=False)
    except Exception as e:
        error = f"Error writing to file with error: {e}"
        status = STATUS_ERROR
        return {"error": error, "message": message , "status": status}
    else:
        message = f"Wrote SearchSploit to file {SEARCHSPLOIT_EXCEL_PATH}"

    message = f"Wrote SearchSploit to file {SEARCHSPLOIT_EXCEL_PATH}"
    return {"data": searchsploit_df, "message": message , "status": status}
    
       
if __name__ == "__main__":
    import  config
    app_config, user_config = config.bootstrap()
    #! Used for testing
    unique_cves = app_config["TEST_CVES"]
    
    # response = download(app_config, user_config)
    # response = transform(app_config)
    response = load(app_config)
    searchsploit_df = response["data"]
    response = search(searchsploit_df, unique_cves)
    
    i = 1
    for row in response["data"]:
        print(f"{i} {row}")
        i = i+1 


    