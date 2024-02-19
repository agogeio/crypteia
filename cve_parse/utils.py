import datetime
import gzip
import os
import shutil
import sys
import time

from datetime import datetime
from pathlib import Path
from urllib.request import urlretrieve

DEBUG = os.environ.get("DEBUG")

# print(f"DEBUG is: {DEBUG}")

ACTIONS = {
    "download": "download",
    "none": "none",
    "terminate" : "terminate"
}

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
        
        if DEBUG == "True": print(f"\nProcessing utils.py -> update_controller() -> file_manager() results")
        if DEBUG == "True": print(f"utils.py -> update_controller() -> file_manager() response: {response}")
        if DEBUG == "True": print(f"utils.py -> update_controller() -> file_manager() response: {type(response)}")
        
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
            
            response = {
                "action" : response["action"],
                "error" : response["error"],
                "message" : response["message"]
            }


def directory_manager(DATA_DIR: str) -> dict:
    """ 
    Receives directory and will validate it exists, if the directory does not exist it will attempt to create it.
    Returns a dict with keys of ["action"], ["message"], and ["error"] if present.
    """
    
    print("\n***** Invoking directory_manager *****\n")
    
    #* Check if the data directory exist.
    #* The directory DOES exist
    if os.path.exists(DATA_DIR):
        
        response = {
                "action": ACTIONS["none"],
                "message": f"{DATA_DIR} was found, no update needed",
            }
        
        return response
    #* If the directory does NOT exist create it
    if not os.path.exists(DATA_DIR):
        # ? For console use only
        if DEBUG == True: print(f"Directory: {DATA_DIR} not found, attempting to create it")
        
        try:
            os.makedirs(DATA_DIR)
        except Exception as e:
            # ? For console use only
            if DEBUG == True: print(f"Error creating: {DATA_DIR} error was: {e}")
            
            #! Update for web implementation 
            response = {
                "action" : ACTIONS["terminate"],
                "message": f"{DATA_DIR} not created",
                "error": f"{e}"
            }
            return response
        
        else:
            if DEBUG == True: print(f"Directory: {DATA_DIR} was created.")
            
            #! Update for web implementation 
            response = {
                "action": "none",
                "message":f"{DATA_DIR} created"
                
            }
            return response


def file_download(URL: str, DATA_FILE_PATH: str) -> dict:
    try:
        urlretrieve(URL, DATA_FILE_PATH)
    except Exception as e:
        response = {
                "action" : ACTIONS["none"],
                "message": f"{URL} not downloaded",
                "error": f"{e}"
            }
        return response
    else:
        response = {
                "message": f"{URL} downloaded to location {DATA_FILE_PATH}",
                "action": ACTIONS["none"]
            }
        return response


def file_manager(AUTO_DOWNLOAD_ALL: str, DATA_AUTO_UPDATE: str, DATA_FILE_PATH: str) -> dict:
    '''
    File accepts a file path. If the file is missing it will check the 
    user_config.js file for AUTO_DOWNLOAD_ALL and DATA_AUTO_UPDATE in the 
    user_config.json file and try to download file.
    
    If AUTO_DOWNLOAD_ALL and DATA_AUTO_UPDATE are both set to false, you can end up with a 
    situation where files are missing and the program must terminate.
    
    The action options in the response are: ["none"], ["download"], and ["terminate"]. 
    The update_controller() will terminate the program if "terminate" is the action in the response
    '''
        
    #* FILE DOES EXIST:
    if os.path.exists(DATA_FILE_PATH):
        #* If FILE DOES EXIST AND AUTO UPDATE IS TRUE!
        if DATA_AUTO_UPDATE == "True":
            response = out_of_date(DATA_FILE_PATH)
            return response
        elif DATA_AUTO_UPDATE == "False":
            message = f"File: {DATA_FILE_PATH} was found, data DATA_AUTO_UPDATE set to 'False' in user_config.json, no download required"
            response = {"message": message, "action": ACTIONS["none"]}
            return response
    #* FILE DOES NOT EXIST:    
    if not os.path.exists(DATA_FILE_PATH):
        #*  FILE DOES NOT EXIST AND AUTO DOWNLOAD SET TO TRUE - SYSTEM CAN CONTINUE TO RUN
        if AUTO_DOWNLOAD_ALL == "True":
            message = f"File: {DATA_FILE_PATH} not found. AUTO_DOWNLOAD_ALL set to 'True' in user_config.json, download required"
            response = {"message": message, "action": ACTIONS["download"]}
            return response
        #*  FILE DOES NOT EXIST AND AUTO DOWNLOAD SET TO FALSE - SYSTEM WILL BE MISSING FILES, CANNOT CONTINUE TO RUN
        elif AUTO_DOWNLOAD_ALL == "False":
            message = f"File: {DATA_FILE_PATH} not found. AUTO_DOWNLOAD_ALL set to 'False' in user_config.json, processing halted"
            response = {"message": message, "action": ACTIONS["terminate"]}
            return response


def out_of_date(FILE_PATH: str) -> dict:
    if os.path.exists(FILE_PATH):
        if DEBUG == "True": print(f"File: {FILE_PATH} was found")
        
        file_path = Path(FILE_PATH)
        creation_time = file_path.stat().st_mtime
        modified_date = datetime.fromtimestamp(creation_time)
        modified_date = modified_date.strftime('%B, %d, %Y')
        
        
        current_date = time.time()
        current_date = datetime.fromtimestamp(current_date)
        current_date = current_date.strftime('%B, %d, %Y')
        
        if modified_date == current_date:
            message = f"Last update time was {modified_date}, files are only updated daily, data will update tomorrow"
            if DEBUG == "True": print(f"{message}")
            
            response = {
                "action" : ACTIONS["none"],
                "message" : message
            }
            
            return response
            
        elif modified_date != current_date:
            
            message = f"Last download time was {modified_date}, data will be updated"
            if DEBUG == "True": print(f"{message}")
            
            response = {
                "action" : ACTIONS["download"],
                "message" : message
            }
            
            return response
        
    if not os.path.exists(FILE_PATH):
        
        message = f"The file {FILE_PATH} does not exist"
        if DEBUG == "True": print(f"{message}")
            
        response = {
            "action" : ACTIONS["download"],
            "message" : message
        }
        
        return response
    
    
def un_gz(gz_file_path, file_path) -> dict:
    """ Un-gz NVD Files """
    try:
        with gzip.open(gz_file_path, 'rb') as nvd_file_path_gz:
            with open(file_path, 'wb') as nvd_file_dir:
                shutil.copyfileobj(nvd_file_path_gz, nvd_file_dir)
    except Exception as e:
        response = {
                "message":f"{file_path} could not be extracted from {gz_file_path}",
                "error": f"{e}"
            }
        return response
    else:
        os.remove(gz_file_path)
        response = {
                "message":f"{file_path} extracted from {gz_file_path}"
            }
        return response  
    

if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    update = update_controller(app_config, user_config, "NOMI")
    