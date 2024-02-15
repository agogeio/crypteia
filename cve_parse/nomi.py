import datetime
import os
import requests
import sys

GITHUB_API_KEY = os.environ.get("NVD_API_KEY")

def get_files():
    owner = 'nomi-sec'
    repo = 'PoC-in-GitHub'
    path = ''  # Use '/' for root directory
    
    current_date_time = datetime.datetime.now()
    date = current_date_time.date()
    current_year = date.year
    years = range(1999, current_year)
    years = ["1999"]
    
    headers = {
    'Authorization': f'{GITHUB_API_KEY}',
    'Accept': 'application/vnd.github.v3+json',
    }

    for year in years:
        url = f'https://api.github.com/repos/{owner}/{repo}/contents/{year}'
        print(url)
        
        response = requests.get(url, headers=headers)
        
        data = response.json()

        # print(response.status_code)
        
        if response.status_code == 200:
            for item in data:
                print(item)
                # print(item["name"])
                # print(item["html_url"])
        elif response.status_code == 403:
            print(f'Unauthorized": {response}')
            print(f'You have likely hit your API rate limit, you may need to update the Nomi dataset less frequently')
            print(f"Disable auto update of the Nomi dataset in your config file")
            sys.exit(f"Terminating job until API rate limit issues are resolved")
        else:
            print(f'Unauthorized": {response}')






if __name__ == "__main__":
    print("Nomi Nomi Nomi")
    
    get_files()