from zipfile import ZipFile as zip_extract
from pprint import pprint
from io import StringIO as str_io
from datetime import datetime as dt
from socket import getservbyport as eng_port
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import pandas as pd


NLZ_DATA = False 
PDF_FILE = "analysis_report.pdf"
CNV = canvas.Canvas(PDF_FILE, pagesize=letter)
def port_2_eng(port):
    try:
        return eng_port(int(port))
    except:
        return 'Unknown'


def zip_reader(fl_name:str):
    data_club = {}
    with zip_extract(fl_name, "r") as zip_file:
        for file_name in zip_file.namelist():
            if file_name.endswith("http.log"):
                with zip_file.open(file_name) as f:
                    df = log_to_df(f)
                    data_club[file_name.split('/')[0]] = df
    return data_club

def log_to_df(log_fl:bytes):
    log = log_fl.readlines()
    rows = []
    for line in log:
        if b'#' not in line:
            row_list = line.decode().split('\t')
            rows.append(row_list)
        else:
            if b'#fields' in line:
                fields = line.split(b"\t")
            elif b'#types' in line:
                types = line.split(b"\t")
    
    #columns = [f'{_[0].decode()} ({_[1].decode()})' for _ in zip(fields, types)]
    columns = [f'{_[0].decode()}' for _ in zip(fields, types)]
    return pd.DataFrame(rows, columns=columns[1:])

def beautify_dfs(dfs:dict):
    for fold_name in dfs:
        df = dfs[fold_name]
        df['ts'] = pd.to_datetime(df['ts'], unit='s' ).dt.strftime('%Y-%m-%d %H:%M:%S')
        df['dest_port_type'] = df['id.resp_p'].apply(port_2_eng)
        dfs[fold_name] = df
    return dfs

def df_4_answers(df_dict:dict):
    analysed_dict = {
            "number_of_logs": len(df_dict),
            "mozilla_based_requests": 0,
            "unique_communications": 0,
            "amazon_folders": 0,
            "non_domain_hosts": 0,
            "banned_hosts_detected": 0,
            "google_was_detected": 0
            }
    port_types_list = []

    for log_name in df_dict:
        dfs = df_dict[log_name]

        # number of destination pcs that have Mozilla Requests
        count = dfs['user_agent'].str.contains('Mozilla/4.0').sum()
        if NLZ_DATA:
            print(f"\nNumber of Mozilla Requests {count} \n")
        analysed_dict["mozilla_based_requests"] += count

        # unique communications
        unique_pair = dfs.groupby(['id.orig_h', 'id.resp_h']).size().reset_index(name='Count') 
        if NLZ_DATA:
            print('\nUnique Communications \n', unique_pair)
        analysed_dict["unique_communications"] += unique_pair['Count'].sum()
        
        # Destination ports and there unique values
        port_types = dfs.groupby(['dest_port_type']).size().reset_index(name='Count')
        if NLZ_DATA:
            print("\nUnique ports \n", port_types)
        port_types_list.extend([_ for _ in port_types["dest_port_type"]])
        
        # How many times folder goes to amazon
        folder = dfs.groupby(['filename']).size().reset_index(name='Count')
        if not folder.empty:
            if NLZ_DATA:
                print('\n How many times was amazon found\n', folder, '\n')
            analysed_dict["amazon_folders"] += folder['Count'].sum()
        
        # No domain found
        ip_rows = dfs[dfs['host'].str.contains(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')]
        if not ip_rows.empty:
            if NLZ_DATA:
                print('\n IPs that don\'t have a domain \n', ip_rows[['id.orig_h','id.resp_h','method','host']])    
            analysed_dict["non_domain_hosts"] += ip_rows.shape[0]

        # detection of banned hosts
        banned_hosts = ['sharql.com', 'linguaflair.de']    
        banned_rows = dfs[dfs['host'].isin(banned_hosts)]    
        if not banned_rows.empty:
            if NLZ_DATA:
                print(f'\nAlert: banned IPs detected {banned_rows}\n')
            analysed_dict["banned_hosts_detected"] += banned_rows.shape[0]        
        
        # google.com detection
        google_detected = dfs[dfs['host'].str.contains('google.com')]
        if not google_detected.empty:
            if NLZ_DATA:
                print(f'\n Google was found \n {google_detected[["id.orig_h","id.resp_h","host"]]}')
            analysed_dict["google_was_detected"] += google_detected.shape[0]
    
    data_dict = {
            'x_axis': [_ for _ in analysed_dict.keys()],
            'y_axis': [_ for _ in analysed_dict.values()]
            }
    data_df = pd.DataFrame(data_dict)

    return data_df, set(port_types_list)

def reporting(analysed_df:dict, port_types:set):
    # Header to the file
    CNV.setFont("Helvetica", 12)
    CNV.drawString(100, 700, "Log Analysis Report")
    CNV.drawString(100, 680, "This is a report that explains what kind of data was found from the logs found in the malware file.")
    
    # Plot for numerical values
    fig1, ax1 = plt.subplots()
    ax1.bar(analysed_df['x_axis'], analysed_df['y_axis'])
    ax1.set_xlabel("Analysed Values")
    ax1.set_ylabel("Count")
    CNV.drawString(100, 600, "Plot 1: Bar Chart")
    CNV.drawImage("plot1.png", 300, 400, width=400, height=300)
    plt.savefig("plot1.png")

    # Plot 2: Pie Chart for categorical values
    #fig2, ax2 = plt.subplots()
    plt.pie([1]* len(port_types), labels=port_types, autopct='%1.1f%%')
    plt.axis('equal')
    plt.title("Ports Found")
    CNV.drawString(200, 320, "Plot 2: Pie Chart")
    CNV.drawImage("plot2.png", 700, 200, width=400, height=300)
    plt.savefig("plot2.png")

    # save and close
    CNV.showPage()
    CNV.save()

    # delete the plot images
    #os.remove("plot1.png")
    #os.remove("plot2.png")


if __name__ == "__main__":
    dfs = zip_reader("c.zip")
    cute_dfs = beautify_dfs(dfs)
    concat_df, port_types = df_4_answers(cute_dfs)
    reporting(concat_df, port_types)
