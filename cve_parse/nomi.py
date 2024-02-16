import datetime
import os
import requests
import sys
import time

import pandas as pd

from pathlib import Path
from datetime import datetime

GITHUB_API_KEY = os.environ.get("NVD_API_KEY")

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


def update_controller(app_config: dict, user_config: dict) -> str:
    """  The update controller processes app and user settings, and will make sure data files are updated once per day """
    
    print("\n***** Evoking the Nomi CVE PoC update controller *****\n")
    
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    NOMI_DATA_DIR = app_config["NOMI_DATA_DIR"]
    NOMI_DATA_FILE = app_config["NOMI_DATA_FILE"]
    NOMI_FILE_PATH = NOMI_DATA_DIR+NOMI_DATA_FILE
    NOMI_DATA_AUTO_UPDATE = user_config["NOMI_DATA_AUTO_UPDATE"]
   
    if AUTO_DOWNLOAD_ALL == "True" or NOMI_DATA_AUTO_UPDATE == "True":
        
        if not os.path.exists(NOMI_DATA_DIR):
            print(f"The directory {NOMI_DATA_DIR} was not found, attempting to create the directory")
        
            try:
                os.makedirs(NOMI_DATA_DIR)
            except Exception as e:
                print(f"There was a problem creating director {NOMI_DATA_DIR}, the error was: {e}")
                sys.exit("Terminating the job, there maybe a permissions issues or you maybe executing from immutable media.")
            else:
                print(f"The directory {NOMI_DATA_DIR} was created.")
        else:
            print(f"The directory {NOMI_DATA_DIR} was found on the system.")

            
        if not os.path.exists(NOMI_FILE_PATH):
            if AUTO_DOWNLOAD_ALL == "True":
                print(f"The file {NOMI_FILE_PATH} was not found and the user_config.json AUTO_DOWNLOAD_ALL is set to True")
                cve_poc_data = load_from_github(app_config)
                #! Need to create the write data to file function which would need the app_config, user_config, and the cve_poc_data
                write_file(app_config, cve_poc_data)
                
        elif os.path.exists(NOMI_FILE_PATH):
            if NOMI_DATA_AUTO_UPDATE == "True":

                print(f"The file at location {NOMI_FILE_PATH} was found, but the user_config.json file flag NOMI_DATA_AUTO_UPDATE is set to True")
                file_path = Path(NOMI_FILE_PATH)
                creation_time = file_path.stat().st_ctime
                creation_date = datetime.fromtimestamp(creation_time)
                creation_date = creation_date.strftime('%B, %d, %Y')
               
                
                current_date = time.time()
                current_date = datetime.fromtimestamp(current_date)
                current_date = current_date.strftime('%B, %d, %Y')
                
                if creation_date == current_date:
                    print(f"Last download time was {creation_date}, files are only updated daily, data will update tomorrow")
                else:
                    cve_poc_data = load_from_github(app_config)
                    write_file(app_config, cve_poc_data)


def write_file(app_config: dict, nomi_data: list):
    """ Writes the Nomi CVE PoC data to a data file """
    
    print("\n***** Writing the Nomi CVE PoC date to a file *****\n")
    
    NOMI_DATA_DIR = app_config["NOMI_DATA_DIR"]
    NOMI_DATA_FILE = app_config["NOMI_DATA_FILE"]
    NOMI_FILE_PATH = NOMI_DATA_DIR+NOMI_DATA_FILE
    
    nomi_df = pd.DataFrame(nomi_data)

    try:
        nomi_df.to_excel(NOMI_FILE_PATH)
    except Exception as e:
        print(f"There was an issue writing the file {NOMI_FILE_PATH}, the error was: {e}")
    else:
        print(f"The file {NOMI_FILE_PATH} was written to the file system.")



if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    update_controller(app_config, user_config)
