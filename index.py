import os
import pandas as pd 

def get_CVEs(path: str = 'VulnerabilityReport.xlsx', sheet: str = 'CVE'):
    api_key = os.environ.get("nvd_key")
    # print(api_key)
    print(path)
    print(sheet)
    
    try:
        df = pd.read_excel(path, sheet_name=sheet)
    except Exception as e:
        print("There was an error:", e)
    finally:
        pass
        print(df)


if __name__ == "__main__":
    print("Welcome to CVE Parse")
    get_CVEs(path='VulnerabilityReport.xlsx', sheet="CVE")