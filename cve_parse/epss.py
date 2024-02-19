import sys


from cve_parse import utils
from urllib.request import urlretrieve

THREAT_INTEL_TYPE = 'CISA_KEV'

def download(app_config: dict, user_config: dict):
    """ Downloads the EPSS C file """
    
    print("\n***** Beginning processing of EPSS files *****\n")
    
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    EPSS_DATA_AUTO_UPDATE = user_config["EPSS_DATA_AUTO_UPDATE"]
    
    EPSS_DOWNLOAD_URL = app_config["download_URLs"]["EPSS_DOWNLOAD_URL"]
    EPSS_DIR=app_config["EPSS_DIR"]
    EPSS_FILE=app_config["EPSS_FILE"]
    EPSS_GZ_FILE=app_config["EPSS_GZ_FILE"]
    EPSS_GZ_PATH=EPSS_DIR+EPSS_GZ_FILE
    EPSS_PATH=EPSS_DIR+EPSS_FILE

    
    #* Checks if the directory exists and will try and create it
    response = utils.directory_manager(EPSS_DIR)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager error: {response["error"]}")
    elif "error" not in response.keys():
        print(f"{THREAT_INTEL_TYPE} directory_manager message: {response["message"]}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")
    
    #* Checks file age and config settings to see if files should be downloaded
    response = utils.file_manager(AUTO_DOWNLOAD_ALL, EPSS_DATA_AUTO_UPDATE, EPSS_PATH)
    if "error" in response.keys():
        print(f"{THREAT_INTEL_TYPE} file_manager error: {response["error"]}")
    elif "error" not in response.keys():
        if response['action'] == 'download':
            response = utils.file_download(EPSS_DOWNLOAD_URL, EPSS_GZ_PATH)
            utils.un_gz(EPSS_GZ_PATH, EPSS_PATH)
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
        elif response['action'] == 'none':
            print(f"{THREAT_INTEL_TYPE} file_download message: {response['message']}")
    else:
        sys.exit(f"Unknown response from the {THREAT_INTEL_TYPE} directory_manager, terminating job. Please check your configuration settings.")

            
            
if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    
    print("In EPSS Module")
    download(app_config, user_config)
    
    
    
    