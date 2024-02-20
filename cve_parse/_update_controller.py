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