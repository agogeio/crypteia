import json
import os
import sys

def bootstrap() -> dict:
    """
    bootstrap looks for the app_config.json and user_config.json
    in the ./config directory.  The function returns two dicts
    one for the app_config and the user_config.
    """
    
    print("\n***** Beginning processing of configuration files *****\n")
    
    APP_CONFIG_FILE = "./config/app_config.json"
    USER_CONFIG_FILE = "./config/user_config.json"
    
    if os.path.isfile(APP_CONFIG_FILE):
        try:
            with open(APP_CONFIG_FILE, 'r', encoding='utf-8') as app_config:
                app_config = json.load(app_config)
        except Exception as e:
            sys.exit(f"Error accessing the application configuration file: {e}")
        else:
            print(f"Application configuration settings loaded from: {APP_CONFIG_FILE}")
    else:
        sys.exit(f"Application configuration file not found at location: {APP_CONFIG_FILE}")
    
    if os.path.isfile(USER_CONFIG_FILE):
        try:
            with open(USER_CONFIG_FILE, 'r', encoding='utf-8') as user_config:
                user_config = json.load(user_config)
        except Exception as e:
            sys.exit(f"Error accessing the user configuration file: {e}")
        else:
            print(f"User configuration settings loaded from: {USER_CONFIG_FILE}")
    else:
        sys.exit(f"User configuration file not found at location: {USER_CONFIG_FILE}")
        

    return app_config, user_config

if __name__ == "__main__":
    app_config, user_config = bootstrap()
    print(json.dumps(app_config, indent=4))
    print(json.dumps(user_config, indent=4))