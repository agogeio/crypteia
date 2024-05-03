import pandas as pd
import plotly.express as px
import streamlit as st

from crypteia import * 
from streamlit_extras.dataframe_explorer import dataframe_explorer

if __name__ == "__main__":

    st.set_page_config(layout="wide", page_title="agoge.io - cryptia")
    st.markdown(
        """
        <style>
            [data-testid=stSidebar] [data-testid=stImage]{
                text-align: center;
                display: block;
                margin-left: auto;
                margin-right: auto;
                width: 100%;
            }
        </style>
        """, unsafe_allow_html=True
    )

    app_config, user_config = config.bootstrap()
    # nvd.download(app_config, user_config)
    
    st.title("agoge.io Cryptia Vulnerability Processing")
    # MARK: STREAMLIT SIDE BAR
    with st.sidebar:
        
        st.image("./images/agogeio_shield.png", width=50)
        
        st.header("agoge Cryptia Vulnerability Prioritization")
        st.write("In the radio button below select if you are uploading a Rapid7 Nexpose or Tenable export file")
        vendor = st.radio("Vulnerability Vendor", ["Tenable", "Rapid7"])
        st.write("You selected:", vendor)
        
        with st.form("VulnerabilityUpload"):
            st.header("Business Email Required")
            st.text_input("We will email you the results of the vulnerability scan analysis", value="first.last@yourbusiness.com")
           
            with st.popover(label="Upload Your Report", use_container_width=True):
                st.markdown("Upload your Vulnerability Export 👋")
                st.write("If you need help exporting your file for use watch the instructional video here")  
                st.markdown("[Need help exporting your report?](https://agoge.io/vulnerability-scan-exports)")
                vendor_report = st.file_uploader("Vulnerability File", type=["xlsx"])
                st.form_submit_button(label="Submit")

    if vendor_report is not None:
        
        if 'vendor_report' not in st.session_state:
            st.session_state['vendor_report'] = vendor_report
            
        success_container = st.container()
        with success_container:
            st.success("Upload was successful")
            
        st.write("The selected vendor was:", vendor)


        cve_tuple = st_vuln_report.extract(vendor, st.session_state['vendor_report'])
        #* nvd_data is a list 
        nvd_data_list = st_nvd.nvd_controller(app_config, unique_cves=cve_tuple)
        
        kev_dataframe = st_kev.create_dataframe(app_config)
        #* kev_dataframe is a DataFrame
        kev_dataframe = kev_dataframe["data"]
        
        kev_report = st_kev.enrich_with_kev(kev_dataframe, nvd_data_list)
        #* kev_report is a list
        kev_report_list = kev_report["data"]

        columns=['cveID', 'vulnStatus', 'baseScore', 'baseSeverity', 'attackVector', 'accessComplexity', 'vectorString', 'isKEV', 'knownRansomwareCampaignUse']
        
        if 'vulnerability_report_dataframe' not in st.session_state:
            vulnerability_report_dataframe = pd.DataFrame(kev_report_list, columns=columns)
            
            filtered = dataframe_explorer(vulnerability_report_dataframe)
            st.data_editor(filtered)
