import glob
import os
import re
import json
import time
import ipaddress
import requests
#email functions libraries:
import smtplib
from string import Template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

api_key = <omitted>
email_addrs = <omitted>
myaddr = <omitted>

def email_NOC(NOC_logs):
    print('This function will send these IPs to the NOC')
    print(NOC_logs)

def email_ITSEC(ITSEC_logs, null_logs):
    print('This function will send these IPs to IT Security', ITSEC_logs,". Null:",null_logs)

def abuseipdb_check(ip, days, NOC_logs, ITSEC_logs, null_logs):
    # DEBUG print("checking ip",ip)
    req = "https://www.abuseipdb.com/check/{}/json?key={}&days={}".format(ip, api_key, days)
    info = requests.get(req).json()
    # DEBUG print(info)
    if not info:
        # DEBUG print("IF NOT INFO loop\n\n")
        null_logs.append(ip)
    elif type(info) is list:
        log = info[0]
        isWhitelisted = log['isWhitelisted']
        abuseConfidenceScore = int(log['abuseConfidenceScore'])
    else:
        # DEBUG print("info type is:", type(info))
        null_logs.append(ip)

    # DEBUG print("abuse confidence score is", abuseConfidenceScore," is whitelisted?", isWhitelisted)
    if abuseConfidenceScore == 0:
        null_logs.append(ip)
        #DEBUG print('appended to null')
    elif 0 < abuseConfidenceScore <= 30:
        ITSEC_logs.append(ip)
        # DEBUG print('appended to ITSEC')
    elif 30 < abuseConfidenceScore <= 100:
        NOC_logs.append(ip)
        # DEBUG print('appended to NOC')
    else:
        # DEBUG print('unable to process')
        null_logs.append(ip)

def get_latest_file():
    list_of_files = glob.glob('./Log_Files/*')
    latest_file = max(list_of_files, key=os.path.getctime)
    ofile = open(latest_file, "r")
    recent_data = ofile.read()
    return(recent_data)

def isolate_ip(data):
    rgx = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    rgxdata = re.findall(rgx, data)
    return (rgxdata)

def main():
    NOC_logs = []
    ITSEC_logs = []
    null_logs = []
    days = 30
    data = get_latest_file()
    # DEBUG print("obtained lateset file")
    ipaddrs = isolate_ip(data)
    # DEBUG print ("successfully obtained ip addr:",ipaddrs)
    for ip in ipaddrs:
        if ipaddress.ip_address(ip).is_private is False:
            time.sleep(1)
            abuseipdb_check(ip, days, NOC_logs, ITSEC_logs, null_logs)
    # DEBUG print("IP addresses appended to NOC:", NOC_logs)
    # DEBUG print("IP addresses appended to IT SEC:", ITSEC_logs)
    # DEBUG print("IP addresses returned as null or no information:", null_logs)
    email_NOC(NOC_logs)
    email_ITSEC(ITSEC_logs, null_logs)

if __name__ == '__main__':
    main()
