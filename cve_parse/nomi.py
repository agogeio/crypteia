import datetime
import os
import requests
import sys

import pandas as pd

from cve_parse import utils
from datetime import datetime

GITHUB_API_KEY = os.environ.get("NVD_API_KEY")

ACTIONS = {
    "download": "download",
    "none": "none",
    "terminate" : "terminate"
}

THREAT_INTEL_TYPE = 'NOMI'

def create_dataframe(app_config: dict) -> pd.DataFrame:
    """ Returns the Nomi dataset as a pd.Dataframe """
    
    print("\n***** Using local Nomi file to load into DataFrame *****\n")
    
    NOMI_DIR = app_config["NOMI_DIR"]
    NOMI_DATA_FILE = app_config["NOMI_DATA_FILE"]
    NOMI_FILE_PATH = NOMI_DIR+NOMI_DATA_FILE
    
    try:
        nomi_df = pd.read_excel(NOMI_FILE_PATH, usecols=["cve", "url"])
    except Exception as e:
        sys.exit(f'Error loading {NOMI_FILE_PATH} file with error: {e}')
    else:
        print(f"Loaded the following file into DataFrame with success: {NOMI_FILE_PATH}")
        
    return nomi_df


def load_from_github(app_config: dict) -> list:
    """ Loads CVE PoC data from the Nomi GitHub repo """

    NOMI_GITHUB_OWNER = app_config["NOMI_GITHUB_OWNER"]
    NOMI_GITHUB_REPO = app_config["NOMI_GITHUB_REPO"]

    print(f"\n***** Beginning processing of loading CVE PoC data from {NOMI_GITHUB_REPO} *****\n")
    
    cve_poc_data = []
    
    current_date_time = datetime.now()
    date = current_date_time.date()
    current_year = date.year
    cve_years = list(range(1999, current_year+1))
    
    headers = {
    'Authorization': f'{GITHUB_API_KEY}',
    'Accept': 'application/vnd.github.v3+json',
    }
    
    for year in cve_years:
        url = f'https://api.github.com/repos/{NOMI_GITHUB_OWNER}/{NOMI_GITHUB_REPO}/contents/{year}'
        try:
            print(f"Sending request to GitHub data at: {url}")
            response = requests.get(url, headers=headers)
        except Exception as e:
            sys.exit(f"Error when requesting {NOMI_GITHUB_REPO} data, the error was: {e}")
        else:
            data = response.json()

            if response.status_code == 200:
                for item in data:
                    cve_list =item["name"].split(".")
                    cve = cve_list[0]
                    html_url = item["html_url"]
                    
                    cve_poc = {
                        "cve": cve,
                        "url": html_url
                    }
                    cve_poc_data.append(cve_poc)
            elif response.status_code == 403:
                print(f'Unauthorized": {response}')
                print(f'You have likely hit your API rate limit, you may need to update the Nomi dataset less frequently')
                print(f"Disable auto update of the Nomi dataset in your config file")
                sys.exit(f"Terminating job until API rate limit issues are resolved")
            else:
                print(f'Unauthorized": {response}')
    
    return cve_poc_data


def download(app_config: dict, user_config: dict) -> str:
    """  The update controller processes app and user settings, and will make sure data files are updated once per day """
    
    print("\n***** Evoking the Nomi CVE PoC update controller *****\n")
    
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    NOMI_DATA_AUTO_UPDATE = user_config["NOMI_DATA_AUTO_UPDATE"]
    
    NOMI_DIR = app_config["NOMI_DIR"]
    NOMI_DATA_FILE = app_config["NOMI_DATA_FILE"]
    
    NOMI_FILE_PATH = NOMI_DIR+NOMI_DATA_FILE
    
    #* Checks if the directory exists and will try and create it
    response = utils.directory_manager(NOMI_DIR)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager error: {response["error"]}")
    elif "error" not in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager message: {response["message"]}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")
    
    #* Checks file age and config settings to see if files should be downloaded
    response = utils.file_manager(AUTO_DOWNLOAD_ALL, NOMI_DATA_AUTO_UPDATE, NOMI_FILE_PATH)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} file_manager error: {response["error"]}")
    elif "error" not in response.keys():
        if response['action'] == 'download':
            #* Nomi needs many files, so we do not use the files_download function in utils
            nomi_data = load_from_github(app_config)
            response = write_file(app_config, nomi_data)
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
        elif response['action'] == 'none':
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")


#! Update the responses
def write_file(app_config: dict, nomi_data: list) -> dict:
    """ Writes the Nomi CVE PoC data to a data file """
    
    print("\n***** Writing the Nomi CVE PoC date to a file *****\n")
    
    NOMI_DIR = app_config["NOMI_DIR"]
    NOMI_DATA_FILE = app_config["NOMI_DATA_FILE"]
    NOMI_FILE_PATH = NOMI_DIR+NOMI_DATA_FILE
    
    nomi_df = pd.DataFrame(nomi_data)

    try:
        nomi_df.to_excel(NOMI_FILE_PATH, index=False)
    except Exception as e:
        message = f"Error writing file: {NOMI_FILE_PATH}, the error was: {e}"
        response = {
            "action" : ACTIONS["none"],
            "message" : message,
            "error" : f'{e}'
        }
    else:
        message = f"File: {NOMI_FILE_PATH} was written to the file system at location."
        response = {
            "action" : ACTIONS["none"],
            "message" : message
        }
        
        return response


if __name__ == "__main__":
    import config
    
    nvd_data = [['CVE-2016-2183', 'Modified', 7.5, 'HIGH', 'NETWORK', 'LOW'], 
            ['CVE-2023-23375', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
            ['CVE-2023-28304', 'Analyzed', 7.8, 'HIGH', 'LOCAL', 'LOW'], 
            ['CVE-2022-31777', 'Analyzed', 5.4, 'MEDIUM', 'NETWORK', 'LOW'], 
            ['CVE-2023-4128', 'Rejected', 'None', 'None', 'None', 'None'], 
            ['CVE-2015-2808', 'Modified', 5.0, 'None', 'NETWORK', 'LOW']]
    
    app_config, user_config = config.bootstrap()
    download(app_config, user_config)
