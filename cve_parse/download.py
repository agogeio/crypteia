import gzip
import os
import shutil
import sys

from urllib.request import urlretrieve


def epss(app_config: dict, user_config: dict):
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
        if user_config["AUTO_UPDATE_EPSS_DATA"] == "True":
            print("EPSS is configured for auto update, downloading EPSS update")
            EPSS_download = True
        elif user_config["AUTO_UPDATE_EPSS_DATA"] == "False":
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


def exploitdb(app_config: dict, user_config: dict):
    """ Downloads the EXPLOITDB XML file """
    
    print("\n***** Beginning processing of EPSS files *****\n")
    
    EXPLOITDB_DOWNLOAD_URL = app_config["download_URLs"]["EXPLOITDB_DOWNLOAD_URL"]
    EXPLOITDB_DIR=app_config["EXPLOITDB_DIR"]
    EXPLOITDB_XML_FILE=app_config["EXPLOITDB_XML_FILE"]
    EXPLOITDB_PATH=EXPLOITDB_DIR+EXPLOITDB_XML_FILE
    
    ExploitDB_download = False
    
    if os.path.isfile(EXPLOITDB_PATH):
        print(f"Existing ExploitDB XML file located at: {EXPLOITDB_PATH}")
        if user_config["AUTO_UPDATE_EXPLOITDB_DATA"] == "True":
            print("ExploitDB is configured for auto update, downloading ExploitDB data.")
            ExploitDB_download = True
        elif user_config["AUTO_UPDATE_KEV_DATA"] == "False":
            print("ExploitDB is not configured for auto update, no ExploitDB update will be downloaded.")
            print("Warning: you may be using an outdated version of the ExploitDB data set")
    elif not os.path.isfile(EXPLOITDB_PATH):
        print(f"No existing ExploitDB file found at location: {EXPLOITDB_PATH}")
        if user_config["AUTO_DOWNLOAD_ALL"] == "True":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, ExploitDB data will be downloaded")
            ExploitDB_download = True
        elif user_config["AUTO_DOWNLOAD_ALL"] == "False":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, ExploitDB data will not be downloaded")    
        else:
            sys.exit("No ExploitDB File found, error processing user config settings, terminating program")
        
    if ExploitDB_download == True:
        try:
            if not os.path.exists(EXPLOITDB_DIR):
                os.makedirs(EXPLOITDB_DIR)
                print(f"Creating directory {EXPLOITDB_DIR}")
            
            urlretrieve(url=EXPLOITDB_DOWNLOAD_URL, filename=EXPLOITDB_PATH)
        except Exception as e:
            sys.exit(f"Failed to process ExploitDB file: {e}")
        else:
            print(f"Updated ExploitDB file at: {EXPLOITDB_PATH}") 


def kev(app_config: dict, user_config: dict):
    """ Downloads the KEV JSON file """
    
    print("\n***** Beginning processing of CISA KEV files *****\n")
    
    CISA_KEV_DOWNLOAD_URL = app_config["download_URLs"]["CISA_KEV_DOWNLOAD_URL"]
    CISA_KEV_DIR=app_config["CISA_KEV_DIR"]
    CISA_KEV_FILE=app_config["CISA_KEV_FILE"]
    CISA_KEV_PATH=CISA_KEV_DIR+CISA_KEV_FILE
    
    CISA_KEV_download = False
    
    if os.path.isfile(CISA_KEV_PATH):
        print(f"Existing CISA KEV file located at: {CISA_KEV_PATH}")
        if user_config["AUTO_UPDATE_KEV_DATA"] == "True":
            print("CISA KEV is configured for auto update, downloading CISA KEV update")
            CISA_KEV_download = True
        elif user_config["AUTO_UPDATE_KEV_DATA"] == "False":
            print("CISA KEV is not configured for auto update, no CISA KEV update will be downloaded.")
            print("Warning, you may be using an outdated version of the CISA KEV list")
    elif not os.path.isfile(CISA_KEV_PATH):
        print(f"No existing CISA KEV file found at location: {CISA_KEV_PATH}")
        if user_config["AUTO_DOWNLOAD_ALL"] == "True":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, CISA KEV will be downloaded")
            CISA_KEV_download = True
        elif user_config["AUTO_DOWNLOAD_ALL"] == "False":
            print(f"Auto download set to {user_config['AUTO_DOWNLOAD_ALL']}, CISA KEV will not be downloaded")    
        else:
            sys.exit("No CISA KEV File found, error processing user config settings, terminating program")
        
    if CISA_KEV_download == True:
        try:
            if not os.path.exists(CISA_KEV_DIR):
                os.makedirs(CISA_KEV_DIR)
            urlretrieve(url=CISA_KEV_DOWNLOAD_URL, filename=CISA_KEV_PATH)
        except Exception as e:
            sys.exit(f"Failed to process CISA KEV file with error: {e}")
        else:
            print(f"Updated CISA KEV file at: {CISA_KEV_PATH}")

          
if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    # epss(app_config, user_config)
    # exploitdb(app_config, user_config)
    # kev(app_config, user_config)
