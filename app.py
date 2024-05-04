import pandas as pd
from PIL import Image
# import plotly.express as px
import streamlit as st

from crypteia import * 
from streamlit_extras.dataframe_explorer import dataframe_explorer

if __name__ == "__main__":

    icon = Image.open("images/blue_shield_logo.png")
    st.set_page_config(
        page_title="agoge.io - cryptia",
        page_icon=icon,
        layout="wide", 
        )
    
    with open("css/cryptia.css") as css_file:
        print(css_file)
        st.markdown(f"<style>{css_file.read()}</style>", unsafe_allow_html=True)
    
    #! pip install SQLAlchemy mysqlclient
    # conn = st.connection("auth.db", type="sql")

    app_config, user_config = config.bootstrap()
    # nvd.download(app_config, user_config)
    
    st.title("Cryptia Vulnerability Processing")
    # MARK: STREAMLIT SIDE BAR
    with st.sidebar:
        st.image("./images/agoge_shield_and_text.svg", width=290)
        
        with st.form("VulnerabilityUpload"):
            with st.popover(label="Upload Your Report", use_container_width=True):
                
                st.write("Select Rapid7 Nexpose or Tenable export file")
                vendor = st.radio(" ", ["Tenable", "Rapid7"])
                # st.write("Selected report type:", vendor)

                vendor_report = st.file_uploader("Vulnerability File", type=["xlsx"])
                st.form_submit_button(label="Submit")
        
        st.write("If you need help exporting your file for use watch the instructional video here")  
        st.markdown("[Need help exporting your report?](https://agoge.io/vulnerability-scan-exports)")
               
        st.caption("Created by Steven Aiello @ https://agoge.io")

    # col1, col2 = st.columns(2)
    # col1, col2, col3 = st.columns(3)
    processed_vulnerabilities_count, kev_vulnerability_count, known_ransomware, filtered_vulnerabilities_count = st.columns(4)
    # col1, col2, col3, col4, col5 = st.columns(5)
        
    with processed_vulnerabilities_count:
        st.header("Processed Vulnerabilities")
        processed_vulnerabilities_count_container = st.container()
        if 'processed_vulnerabilities_count' in st.session_state:
            st.write(st.session_state["processed_vulnerabilities_count"])

    with kev_vulnerability_count:
        st.header("Vulnerabilities in CISA KEV")
        kev_vulnerability_count_container = st.container()
        if 'kev_vulnerability_count' in st.session_state:
            st.write(st.session_state["kev_vulnerability_count"])

    with known_ransomware:
        st.header("Ransomware Vulnerabilities")
        known_ransomware_container = st.container()
        if 'known_ransomware' in st.session_state:
            st.write(st.session_state["known_ransomware"])
        
    with filtered_vulnerabilities_count:
        st.header("Prioritized CVEs")
        filtered_vulnerabilities_count_container = st.container()


    
    data_tab, chart_tab = st.tabs(["Vulnerability Data", "Reporting Charts"])

    #! This is the tab with Pandas DataFrame Information 
    with data_tab:
        
        if vendor_report is None:
            # st.stop()
            pass
        
        if vendor_report is not None:
            success = st.empty()
            success.success("Upload was successful")
            
            with st.spinner("Processing and filtering your " + vendor + " report"):
                
                if 'vulnerability_report_dataframe' not in st.session_state:
                    cve_tuple = st_vuln_report.extract(vendor, vendor_report)
                    #* nvd_data is a list 
                    nvd_data_list = st_nvd.nvd_controller(app_config, unique_cves=cve_tuple)
                    kev_dataframe = st_kev.create_dataframe(app_config)
                    #* kev_dataframe is a DataFrame
                    kev_dataframe = kev_dataframe["data"]
                    kev_report = st_kev.enrich_with_kev(kev_dataframe, nvd_data_list)
                    #* kev_report is a list
                    kev_report_list = kev_report["data"]
                    columns=['CVE ID', 'Vuln Status', 'Base Score', 'Base Severity', 'Attack Vector', 'Access Complexity', 'Vector String', 'In CISA KEV', 'Ransomware Reported']
                    vulnerability_report_dataframe = pd.DataFrame(kev_report_list, columns=columns)
                
                    #! This is the unfiltered DataFrame
                    st.session_state["vulnerability_report_dataframe"] = vulnerability_report_dataframe

                    st.session_state["processed_vulnerabilities_count"] = len(st.session_state["vulnerability_report_dataframe"])
                    processed_vulnerabilities_count_container.write(st.session_state["processed_vulnerabilities_count"])

                    st.session_state["kev_vulnerability_count"] = len(vulnerability_report_dataframe[vulnerability_report_dataframe["In CISA KEV"]=="In KEV"])
                    kev_vulnerability_count_container.write(st.session_state["kev_vulnerability_count"])

                    st.session_state["known_ransomware"] = len(vulnerability_report_dataframe[vulnerability_report_dataframe["Ransomware Reported"]=="Known"])
                    known_ransomware_container.write(st.session_state["known_ransomware"])

                filtered = dataframe_explorer(st.session_state["vulnerability_report_dataframe"])
                
                #! This is the filtered dataframe
                st.session_state["filtered_vulnerability_report_dataframe"] = filtered
                
                st.session_state["filtered_vulnerabilities_count"] = len(filtered)
                filtered_vulnerabilities_count_container.write(st.session_state["filtered_vulnerabilities_count"])
                st.data_editor(filtered, hide_index=False)
                success.empty()

    #! This is the tab with Charts 
    with chart_tab:
        
        st.write("Reporting Dashboard")
        
        if 'filtered_vulnerability_report_dataframe' in st.session_state:
            
            av_reporting = st.session_state["filtered_vulnerability_report_dataframe"]
            # print(av_reporting.columns.tolist())

            #! This needs to go into a function that returns av_dict
            av_columns = av_reporting["Attack Vector"].unique().tolist()
            av_data = []
            
            av_network_count = len(av_reporting[av_reporting["Attack Vector"] == "NETWORK"])             
            if av_network_count > 0: av_data.append(av_network_count)
            
            av_adjacent_count = len(av_reporting[av_reporting["Attack Vector"] == "ADJACENT_NETWORK"])
            if av_adjacent_count > 0: av_data.append(av_adjacent_count)
            
            av_local_count = len(av_reporting[av_reporting["Attack Vector"] == "LOCAL"])
            if av_local_count > 0: av_data.append(av_local_count)
            
            av_physical_count = len(av_reporting[av_reporting["Attack Vector"] == "PHYSICAL"])
            if av_physical_count > 0: av_data.append(av_physical_count)
            
            av_none_count = len(av_reporting[av_reporting["Attack Vector"] == "None"])
            if av_none_count > 0: av_data.append(av_none_count)
            
            av_dict = { 
                       "av_type": av_columns,
                       "av_data":av_data
                    }
            #! End Attack Vector
            
            
            #! This needs to go into a function that returns av_dict
            base_severity_columns = av_reporting["Base Severity"].unique().tolist()
            base_severity_data = []
            
            critical_count = len(av_reporting[av_reporting["Base Severity"] == "CRITICAL"])             
            if critical_count > 0: base_severity_data.append(critical_count)
            
            high_count = len(av_reporting[av_reporting["Base Severity"] == "HIGH"])
            if high_count > 0: base_severity_data.append(high_count)
            
            medium_count = len(av_reporting[av_reporting["Base Severity"] == "MEDIUM"])
            if medium_count > 0: base_severity_data.append(medium_count)
            
            low_count = len(av_reporting[av_reporting["Base Severity"] == "LOW"])
            if low_count > 0: base_severity_data.append(low_count)
            
            none_count = len(av_reporting[av_reporting["Base Severity"] == "None"])
            if none_count > 0: base_severity_data.append(none_count)

            base_severity_dict = { 
                    "base_severity_type": base_severity_columns,
                    "base_severity_data":base_severity_data
                }

            base_severity, attack_vector = st.columns(2)
            
            
            with base_severity:
                base_severity_df = pd.DataFrame.from_dict(base_severity_dict)
                st.header("Filtered Base Severity")
                st.bar_chart(data=base_severity_df, use_container_width=True, x="base_severity_type")
                
                
            with attack_vector:
                av_df = pd.DataFrame.from_dict(av_dict)
                st.header("Attack Vector Findings")
                st.bar_chart(data=av_df, use_container_width=True, x="av_type")
        
    

    
