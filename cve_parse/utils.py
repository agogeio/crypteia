import datetime
import gzip
import os
import shutil
import time
import pathlib

from datetime import datetime
from urllib.request import urlretrieve

DEBUG = os.environ.get("DEBUG")

ACTIONS = {
    "download": "download",
    "none": "none",
    "terminate" : "terminate"
}

STATUS_ERROR = 400
STATUS_TERMINATE = 500
STATUS_OK = 200

def directory_manager(DATA_DIR: str) -> dict:
    """
    Receives directory and will validate it exists, if the directory does not exist it will attempt 
    to create it. 

    Args:
        DATA_DIR (str): The path of the directory to be evaluated

    Returns:
        dict: with keys: action, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """

    #* Check if the data directory exist.
    #* The directory DOES exist
    if os.path.exists(DATA_DIR):
        response = {"action": ACTIONS["none"], "message": f"{DATA_DIR} found, no action needed", "status": STATUS_OK}
        return response
    
    #* If the directory does NOT exist try to create it
    if not os.path.exists(DATA_DIR):
        try:
            os.makedirs(DATA_DIR)
        except Exception as e:
            response = {"action" : ACTIONS["terminate"], "error": f"{e}", "message": f"Filed to create {DATA_DIR}", "status": STATUS_TERMINATE}
            return response
        else:
            response = {"action": "none", "message":f"{DATA_DIR} created", "status": STATUS_OK}
            return response


def file_download(URL: str, DATA_FILE_PATH: str) -> dict:
    """
    A general file downloader for general use cases

    Args:
        URL (str): URL of the file to be downloaded
        DATA_FILE_PATH (str): Path on disk where the file should be written

    Returns:
        dict: with keys: action, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    try:
        urlretrieve(URL, DATA_FILE_PATH)
    except Exception as e:
        response = {"action" : ACTIONS["none"], "error": f"{e}", "message": f"{URL} not downloaded", "status": STATUS_ERROR}
        return response
    else:
        response = {"action": ACTIONS["none"], "message": f"{URL} downloaded to location {DATA_FILE_PATH}", "status": STATUS_OK}
        return response


def file_manager(AUTO_DOWNLOAD_ALL: str, DATA_AUTO_UPDATE: str, DATA_FILE_PATH: str) -> dict:
    """
    File accepts a file path. If the file is missing it will check the 
    user_config.js file for AUTO_DOWNLOAD_ALL and DATA_AUTO_UPDATE in the 
    user_config.json file and try to download file.
    
    If AUTO_DOWNLOAD_ALL and DATA_AUTO_UPDATE are both set to false, you can end up with a 
    situation where files are missing and the program must terminate.

    Args:
        AUTO_DOWNLOAD_ALL (str): Defines if datasets will automatically be downloaded if missing, set in the user_config.json file
        DATA_AUTO_UPDATE (str): Defines if datasets will automatically be updated, set in the user_config.json file
        DATA_FILE_PATH (str): If the location of the file to validate

    Returns:
        dict: with keys: action, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    DATA_FILE_PATH = pathlib.Path(DATA_FILE_PATH)
    
    print(f"Validating File: {DATA_FILE_PATH}")
    
    #* FILE DOES NOT EXIST:    
    if not pathlib.Path(DATA_FILE_PATH).is_file():
        #*  FILE DOES NOT EXIST AND AUTO DOWNLOAD SET TO TRUE - SYSTEM CAN CONTINUE TO RUN
        if AUTO_DOWNLOAD_ALL == "True":
            message = f"{DATA_FILE_PATH} not found. AUTO_DOWNLOAD_ALL set to 'True' in user_config.json, download"
            response = {"action": ACTIONS["download"], "message": message, "status": STATUS_OK}
            return response
        #*  FILE DOES NOT EXIST AND AUTO DOWNLOAD SET TO FALSE - SYSTEM WILL BE MISSING FILES, CANNOT CONTINUE TO RUN
        elif AUTO_DOWNLOAD_ALL == "False":
            message = f"{DATA_FILE_PATH} not found. AUTO_DOWNLOAD_ALL set to 'False' in user_config.json, processing terminated"
            response = {"action": ACTIONS["terminate"], "message": message, "status": STATUS_TERMINATE}
            return response
    #* FILE DOES EXIST:
    elif pathlib.Path(DATA_FILE_PATH).is_file():
        #* If FILE DOES EXIST AND AUTO UPDATE IS TRUE!
        if DATA_AUTO_UPDATE == "True":
            response = out_of_date(DATA_FILE_PATH)
            return response
        elif DATA_AUTO_UPDATE == "False":
            message = f"{DATA_FILE_PATH} found, data DATA_AUTO_UPDATE set to 'False' in user_config.json, no download"
            response = { "action": ACTIONS["none"], "message": message, "status": STATUS_OK}
            return response
        

def out_of_date(FILE_PATH: str) -> dict:
    """
    Checks the modified data of the file on disk, if the file was not 
    modified today a "download" action will be returned

    Returns:
        dict: with keys: action, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """

    if pathlib.Path(FILE_PATH).is_file():
        file_path = pathlib.Path(FILE_PATH)
        creation_time = file_path.stat().st_mtime
        modified_date = datetime.fromtimestamp(creation_time)
        modified_date = modified_date.strftime('%B, %d, %Y')
        
        current_date = time.time()
        current_date = datetime.fromtimestamp(current_date)
        current_date = current_date.strftime('%B, %d, %Y')
        
        if modified_date == current_date:
            # print(f"out_of_date() if modified is current date {file_path}")
            message = f"{FILE_PATH} modified {modified_date}, not download"
            response = {"action" : ACTIONS["none"], "message" : message, "status": STATUS_OK}
            return response
            
        elif modified_date != current_date:
            message = f"{FILE_PATH} modified {modified_date}, download"
            response = {"action" : ACTIONS["download"], "message" : message, "status": STATUS_OK}
            return response
        
    if not pathlib.Path(FILE_PATH).is_file():
        message = f"{FILE_PATH} does not exist, download"
        response = {"action" : ACTIONS["download"], "message" : message, "status": STATUS_OK}
        return response


def un_gzip(gz_file_path: str , file_path: str) -> dict:
    """
    General utility to un_gzip downloaded files

    Args:
        gz_file_path (_type_): File path location to the gzipped file
        file_path (_type_): File path location to the unzipped file

    Returns:
        dict: with keys: action, error (if present), message, status (200 for ok, 400 for error, 500 for terminate)
    """
    
    try:
        with gzip.open(gz_file_path, 'rb') as nvd_file_path_gz:
            with open(file_path, 'wb') as nvd_file_dir:
                shutil.copyfileobj(nvd_file_path_gz, nvd_file_dir)
    except Exception as e:
        response = {"action": ACTIONS["none"], "error": f"{e}", "message":f"{file_path} could not be extracted from {gz_file_path}", "status": STATUS_ERROR}
        return response
    else:
        os.remove(gz_file_path)
        response = {"action": ACTIONS["none"], "message":f"{file_path} extracted from {gz_file_path}", "status": STATUS_OK}
        return response


if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()

    NVD_DATA_DIR = app_config["NVD_DATA_DIR"]
    NVD_DATA_FILES = app_config["NVD_DATA_FILES"]
    
    for NVD_DATA_FILE in NVD_DATA_FILES:
        response = file_manager("True", "True", f"{NVD_DATA_DIR+NVD_DATA_FILE}")
        
        if "error" in response.keys():
                print(f"{response["error"]}")
        elif "error" not in response.keys():
                
            if response['action'] == 'download':
                # response = file_download(data["nvd_url"], data["nvd_gz_file_path"])
                # un_gzip(data["nvd_gz_file_path"], data["nvd_file_path"])
                print(f"{response['message']}")
                # merge = True
                
            elif response['action'] == 'none':
                print(f"{response['message']}")
        else:
            print(f"Unknown response from the directory_manager, terminating job. Please check your configuration settings.")
