import datetime
import os
import sys
import time

from datetime import datetime
from pathlib import Path
from urllib.request import urlretrieve

DEBUG = os.environ.get("DEBUG")

def update_controller(app_config: dict, user_config: dict, threat_intel: str) -> None:
    """  The update controller processes app and user settings, and will make sure data files are updated once per day """
    
    print("\n***** Invoking the update_controller *****\n")
    
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    
    #* Set variables based on threat intel feed requested    
    if threat_intel == "CISA_KEV":
        DATA_DIR = app_config["CISA_KEV_DIR"]
        DATA_FILE = app_config["CISA_KEV_FILE"]
        DATA_FILES = []
        DATA_FILES.append(DATA_FILE)
        DATA_AUTO_UPDATE = user_config["CISA_KEV_DATA_AUTO_UPDATE"]
    elif threat_intel == "EPSS":
        DATA_DIR = app_config["EPSS_DIR"]
        DATA_FILE = app_config["EPSS_FILE"]
        DATA_FILES = []
        DATA_FILES.append(DATA_FILE)
        DATA_AUTO_UPDATE = user_config["EPSS_DATA_AUTO_UPDATE"] 
    elif threat_intel == "EXPLOITDB":
        DATA_DIR = app_config["EXPLOITDB_DIR"]
        DATA_FILE = app_config["EXPLOITDB_XML_FILE"]
        DATA_FILES = []
        DATA_FILES.append(DATA_FILE)
        DATA_AUTO_UPDATE = user_config["EXPLOITDB_DATA_AUTO_UPDATE"]
    elif threat_intel == "NOMI":
        DATA_DIR = app_config["NOMI_DATA_DIR"]
        DATA_FILE = app_config["NOMI_DATA_FILE"]
        DATA_FILES = []
        DATA_FILES.append(DATA_FILE)
        DATA_AUTO_UPDATE = user_config["NOMI_DATA_AUTO_UPDATE"]
    elif threat_intel == "NVD":
        DATA_DIR = app_config["NVD_DATA_DIR"]
        DATA_FILES = app_config["NVD_DATA_FILES"]
        DATA_AUTO_UPDATE = user_config["NVD_DATA_AUTO_UPDATE"]

    #* Submit directory path for verification and creation if needed
    response = directory_manager(DATA_DIR)
    
    if DEBUG == "True":
        print(f"\nProcessing utils.py -> update_controller() -> directory_manager() results")
        print(f"utils.py -> update_controller() -> directory_manager() response: {response}")
    
        if "error" not in response.keys():
            print(f"utils.py -> update_controller() -> directory_manager() response: {response["message"]}")
        elif "error" in response.keys():
            print(f"utils.py -> update_controller() -> directory_manager() error: {response["error"]}")
        else:
            print(f"utils.py -> update_controller() -> directory_manager() Unknown status")


    #* Check if files exist and when they were created
    for CURRENT_DATA_FILE in DATA_FILES:
        DATA_FILE_PATH = DATA_DIR+CURRENT_DATA_FILE
        response = file_manager(AUTO_DOWNLOAD_ALL, DATA_AUTO_UPDATE, DATA_FILE_PATH)
        
        if DEBUG == "True":
            print(f"\nProcessing utils.py -> update_controller() -> file_manager() results")
            print(f"utils.py -> update_controller() -> file_manager() response: {response}")
            print(f"utils.py -> update_controller() -> file_manager() response: {type(response)}")
        
        #* Checking for errors from file_manager response
        if "error" not in response.keys():
            print(f"utils.py -> update_controller() -> file_manager() response: {response["message"]}")
        elif "error" in response.keys():
            print(f"utils.py -> update_controller() -> file_manager() error: {response["error"]}")
        else:
            print(f"utils.py -> update_controller() -> file_manager() Unknown error status")

        #* Checking for action from file_manager response
        if response["action"] == "terminate":
            sys.exit(f"{DATA_FILE_PATH} was not found and AUTO_DOWNLOAD_ALL in the user_config.json file is set to False. Critical error, terminating program.")
        
        elif response["action"] == "none":
            if DATA_AUTO_UPDATE == "True":
                print(f"File: {DATA_FILE_PATH} was found, but it is up to date")
            elif DATA_AUTO_UPDATE == "False":
                print(f"File: {DATA_FILE_PATH} was found, but the user_config.js file {threat_intel}_DATA_AUTO_UPDATE is set to False. Your data maybe out of date.")
            
        elif response["action"] == "download":
            print(f"Downloading: {DATA_FILE_PATH}")
            # response = file_download(URL, DATA_FILE_PATH)
        

def directory_manager(DATA_DIR) -> dict:
    """ Receives directory path, validates existence, creates if non-existent """
    
    print("\n***** Invoking directory_manager *****\n")
    
    #* Check if the data directory exist.
    if os.path.exists(DATA_DIR):
        
        response = {
                "message":f"{DATA_DIR} was found",
            }
        
        return response
    #* If the directory does not exist create it
    if not os.path.exists(DATA_DIR):
        # ? For console use only
        print(f"Directory: {DATA_DIR} not found, attempting to create it")
        try:
            os.makedirs(DATA_DIR)
        except Exception as e:
            # ? For console use only
            print(f"Error creating: {DATA_DIR} error was: {e}")
            
            #! Update for web implementation 
            response = {
                "message":f"{DATA_DIR} not created",
                "error": f"{e}"
            }
            return response
        
        else:
            print(f"Directory: {DATA_DIR} was created.")
            
            #! Update for web implementation 
            response = {
                "message":f"{DATA_DIR} created",
            }
            return response


def file_download(URL, DATA_FILE_PATH) -> dict:
    
    if DEBUG == "True":
        print(f"\nIn file_download\n")
    
    try:
        urlretrieve(URL, DATA_FILE_PATH)
    except Exception as e:
        response = {
                "message":f"{URL} not downloaded",
                "error": f"{e}"
            }
        return response
    else:
        response = {
                "message":f"{URL} downloaded to location {DATA_FILE_PATH}",
            }
        return response


def file_manager(AUTO_DOWNLOAD_ALL, DATA_AUTO_UPDATE, DATA_FILE_PATH) -> dict:
    '''
    File manager looks at the file path. If the file is missing it will check the 
    user_config.js file for AUTO_DOWNLOAD_ALL and DATA_AUTO_UPDATE to try and download files.
    
    If AUTO_DOWNLOAD_ALL and DATA_AUTO_UPDATE are both set to false, you can end up with a 
    situation where files are missing and the program must terminate.
    
    The action options in the response are: none, download, and terminate. 
    The update_controller() will terminate the program if "terminate" is the action in the response
    '''
    
    response = {}
    creation_date = ""
    current_date = ""

    if DEBUG == "True":
        print(f"utils.py -> file_manager() -> AUTO_DOWNLOAD_ALL: {AUTO_DOWNLOAD_ALL}")
        print(f"utils.py -> file_manager() -> DATA_AUTO_UPDATE: {DATA_AUTO_UPDATE}")
        print(f"utils.py -> file_manager() -> DATA_FILE_PATH: {DATA_FILE_PATH}")

    #! This section checks if the file exists and the age of the file
    #! If the file does not exist and AUTO_DOWNLOAD_ALL is set to True the file will be flagged for download
    #! If the file does exist and _DATA_AUTO_UPDATE is set to True, check to see if the file was updated today (cont. next line)
        #! If the file was already downloaded today, do not download. If the file is more than 1 day old re-download
        
    #* FILE DOES EXIST:
    if os.path.exists(DATA_FILE_PATH):
        if DEBUG == "True":
            print(f"File: {DATA_FILE_PATH} was found")
            
        #* Checks creation date of the file on disk 
        data_file = Path(DATA_FILE_PATH)
        #! Do I want create time .st_ctime or modified time .st_mtime?
        #! creation_time = data_file.stat().st_ctime
        creation_time = data_file.stat().st_mtime
        creation_date = datetime.fromtimestamp(creation_time)
        creation_date = creation_date.strftime('%B, %d, %Y')
        
        #* Gets the current date
        current_date = time.time()
        current_date = datetime.fromtimestamp(current_date)
        current_date = current_date.strftime('%B, %d, %Y')

        #* If FILE DOES EXIST AND AUTO UPDATE IS TRUE!
        if DATA_AUTO_UPDATE == "True":
            if DEBUG == "True":
                print(f"In DATA_AUTO_UPDATE")

            #* Compares file creation date with the current date
            if creation_date == current_date:
                message = f"{DATA_FILE_PATH} was created on {creation_date}, data already updated today, no download required"
                
                response = {
                    "message": message,
                    "action": "none"
                    }
                
                return response
                
            elif creation_date != current_date:
                message = f"File: {DATA_FILE_PATH} was created on {creation_date}, data will be updated, download required"
                response = {
                    "message": message,
                    "action": "download"
                    }
                
                return response
            
        elif DATA_AUTO_UPDATE == "False":
            message = f"File: {DATA_FILE_PATH} was found, created on {creation_date}, data DATA_AUTO_UPDATE set to false, no download required"
            response = {
                "message": message,
                "action": "none"
                }
            
            return response

        
    #* FILE DOES NOT EXIST:    
    if not os.path.exists(DATA_FILE_PATH):
        print(f"File: {DATA_FILE_PATH} not found")
        
        #*  FILE DOES NOT EXIST AND AUTO DOWNLOAD SET TO TRUE - SYSTEM CAN CONTINUE TO RUN
        if AUTO_DOWNLOAD_ALL == "True":
            message = f"File: {DATA_FILE_PATH} not found. AUTO_DOWNLOAD_ALL set to 'True' in user_config.json, download required"
            response = {
                "message": message,
                "action": "download"
                }
            
            return response

        #*  FILE DOES NOT EXIST AND AUTO DOWNLOAD SET TO FALSE - SYSTEM WILL BE MISSING FILES, CANNOT CONTINUE TO RUN
        elif AUTO_DOWNLOAD_ALL == "False":
            message = f"File: {DATA_FILE_PATH} not found. AUTO_DOWNLOAD_ALL set to 'False' in user_config.json, processing halted"
            response = {
                "message": message,
                "action": "terminate"
                }
            
            return response
    

                    
if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    update = update_controller(app_config, user_config, "NOMI")
    