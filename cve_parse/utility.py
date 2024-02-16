import datetime
import os
import sys
import time

from pathlib import Path
from datetime import datetime


def update_controller(app_config: dict, user_config: dict, data_dir: str, data_file: str) -> str:
    """  The update controller processes app and user settings, and will make sure data files are updated once per day """
    
    print("\n***** Evoking the Nomi CVE PoC update controller *****\n")
    
    AUTO_DOWNLOAD_ALL = user_config["AUTO_DOWNLOAD_ALL"]
    DATA_AUTO_UPDATE = user_config["DATA_AUTO_UPDATE"]
    
    DATA_DIR = data_dir
    DATA_FILE = data_file
    FILE_PATH = DATA_DIR+DATA_FILE
    
    
   
    if AUTO_DOWNLOAD_ALL == "True" or DATA_AUTO_UPDATE == "True":
        
        if not os.path.exists(DATA_DIR):
            print(f"The directory {DATA_DIR} was not found, attempting to create the directory")
        
            try:
                os.makedirs(DATA_DIR)
            except Exception as e:
                print(f"There was a problem creating director {DATA_DIR}, the error was: {e}")
                sys.exit("Terminating the job, there maybe a permissions issues or you maybe executing from immutable media.")
            else:
                print(f"The directory {DATA_DIR} was created.")
        else:
            print(f"The directory {DATA_DIR} was found on the system.")

            
        if not os.path.exists(FILE_PATH):
            if AUTO_DOWNLOAD_ALL == "True":
                print(f"The file {FILE_PATH} was not found and the user_config.json AUTO_DOWNLOAD_ALL is set to True")
                
                #? Return True of False if download
                #! Need to create the write data to file function which would need the app_config, user_config, and the cve_poc_data
                cve_poc_data = load_from_github(app_config, user_config)
                #! Need to create the write data to file function which would need the app_config, user_config, and the cve_poc_data
                write_file(app_config, cve_poc_data)
                
        elif os.path.exists(FILE_PATH):
            if DATA_AUTO_UPDATE == "True":

                print(f"The file at location {FILE_PATH} was found, but the user_config.json file flag NOMI_DATA_AUTO_UPDATE is set to True")
                data_file = Path(FILE_PATH)
                creation_time = data_file.stat().st_ctime
                creation_date = datetime.fromtimestamp(creation_time)
                creation_date = creation_date.strftime('%B, %d, %Y')
               
                
                current_date = time.time()
                current_date = datetime.fromtimestamp(current_date)
                current_date = current_date.strftime('%B, %d, %Y')
                
                if creation_date == current_date:
                    print(f"Last download time was {creation_date}, files are only updated daily, data will update tomorrow")
                else:
                    #? Return True of False if download
                    cve_poc_data = load_from_github(app_config, user_config)
                    #? Write the file
                    write_file(app_config, cve_poc_data)
                    
                    
if __name__ == "__main__":
    import config
    app_config, user_config = config.bootstrap()
    update_controller(app_config, user_config)