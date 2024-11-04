import pandas as pd

def inspector(vuln_file):
    """Extracts CVEs from AWS Inspector vulnerability report

    Args:
        vuln_file (str): Path to the AWS Inspector Excel report file
    """
    
    print("\n***** Beginning processing of user supplied AWS Inspector vulnerability file *****\n")
    
    USER_VULNERABILITY_SHEET_NAME = "CVE"
    USER_VULNERABILITY_COLUMN_NAME = "Vulnerability Id"
    
    cols = [USER_VULNERABILITY_COLUMN_NAME]
    cve_list = []
    cve_tuple = ()
    
    try:
        print(f"Processing report: {vuln_file}")
        df = pd.read_excel(vuln_file, sheet_name=USER_VULNERABILITY_SHEET_NAME, usecols=[USER_VULNERABILITY_COLUMN_NAME])
        df = df.dropna(subset=cols[0])
        cve_list = df[df['Vulnerability Id'].str.startswith('CVE')]['Vulnerability Id'].tolist()
        cve_tuple = tuple(cve_list)
        return cve_tuple
        
    except Exception as e:
        return f'error: {e}'

if __name__ == "__main__":
    results = inspector('./import/Inspector.xlsx')
    print(results)
    