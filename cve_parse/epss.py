import gzip
import os
import shutil
import sys

from urllib.request import urlretrieve


def download(app_config: dict, user_config: dict):
    """ Downloads the EPSS C file """
    
    print("\n***** Beginning processing of EPSS files *****\n")
    
    EPSS_DOWNLOAD_URL = app_config["download_URLs"]["EPSS_DOWNLOAD_URL"]
    EPSS_DIR=app_config["EPSS_DIR"]
    EPSS_FILE=app_config["EPSS_FILE"]
    EPSS_GZ_FILE=app_config["EPSS_GZ_FILE"]
    EPSS_GZ_PATH=EPSS_DIR+EPSS_GZ_FILE
    EPSS_PATH=EPSS_DIR+EPSS_FILE
    
    EPSS_download = False
    
    if os.path.isfile(EPSS_PATH):
        print(f"Existing EPSS file located at: {EPSS_PATH}")
        if user_config["EPSS_DATA_AUTO_UPDATE"] == "True":
            print("EPSS is configured for auto update, downloading EPSS update")
            EPSS_download = True
        elif user_config["EPSS_DATA_AUTO_UPDATE"] == "False":
            print("EPSS is not configured for auto update, no EPSS update will be downloaded.")
            print("Warning, you may be using outdated EPSS data")
    elif not os.path.isfile(EPSS_PATH):
        print(f"No existing EPSS file found at location: {EPSS_PATH}")
        if user_config["AUTO_DOWNLOAD_ALL"] == "True":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, EPSS will be downloaded")
            EPSS_download = True
        elif user_config["AUTO_DOWNLOAD_ALL"] == "False":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, EPSS will not be downloaded")    
        else:
            sys.exit("No EPSS file found, error processing user config settings, terminating program")
        
    if EPSS_download == True:
        try:
            if not os.path.exists(EPSS_DIR):
                os.makedirs(EPSS_DIR)
                print(f"Creating directory {EPSS_DIR}")

            urlretrieve(url=EPSS_DOWNLOAD_URL, filename=EPSS_GZ_PATH)

            with gzip.open(EPSS_GZ_PATH, 'rb') as epss_gz:
                with open(EPSS_PATH, 'wb') as epss_csv:
                    shutil.copyfileobj(epss_gz, epss_csv)

            os.remove(EPSS_GZ_PATH)
        except Exception as e:
            sys.exit(f"Failed to process EPSS file: {e}")
        else:
            print(f"Updated EPSS file at: {EPSS_PATH}")
            
            
if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    
    print("In EPSS Module")
    download(app_config, user_config)
    
    
    
    