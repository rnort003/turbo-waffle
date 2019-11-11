#!/usr/bin/env python3
import glob
import os
import re
import json
import time
import ipaddress
import requests
import configexample as cfg
#email functions libraries:
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

api_key = cfg.bones['api_key']
ITSEC_email = cfg.bones['ITSEC_email']
NOC_email = cfg.bones['NOC_email']
myaddr = cfg.bones['user']
pw = cfg.bones['passwd']
tmp = cfg.bones['tmp']
#cc = cfg.bones['cc']

def email_NOC(NOC_logs):
    # DEBUG print('This function will send these IPs to the NOC', NOC_logs)
    message = MIMEMultipart("alternative")
    message['Subject'] = "Please review these IP addresses found from ECOM DDI"
    message['From'] = "ITSecurity@company.com"
    message['To'] = NOC_email

    text = (
    "Hi NOC,\n"
    "Please block the following ip addresses on the digital and ecom f5's for "
    "72 hours:\n"
    "{}\n\n"
    "Thanks,\n"
    "turbo-waffle".format(NOC_logs))

    p1 = MIMEText(text, "plain")
    message.attach(p1)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(myaddr, pw)
        server.sendmail(
            myaddr, NOC_email, message.as_string()
        )

def email_ITSEC(ITSEC_logs, null_logs, NOC_logs):
    # DEBUG print('This function will send these IPs to IT Security', ITSEC_logs,". Null:",null_logs)
    message = MIMEMultipart("alternative")
    message['Subject'] = "Review these IP addresses found from ECOM DDI"
    message['From'] = "ITSecurity@company.com"
    message['To'] = ITSEC_email

    text = (
    "Hi IT Security,\n"
    "Please review these IP addresses:\n"
    "Consider blocking these IP's: {}\n"
    "\nI could not find any information on these: {}\n"
    "\nWe sent the NOC these IP's to block (72 hrs): {}\n\n"
    "Thanks,\n"
    "turbo-waffle".format(ITSEC_logs,null_logs,NOC_logs))
    p1 = MIMEText(text, "plain")
    message.attach(p1)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(myaddr, pw)
        server.sendmail(
            myaddr, ITSEC_email, message.as_string()
        )

def abuseipdb_check(uip, bIPs, days, NOC_logs, ITSEC_logs, null_logs):
    print("checking ip",uip)
    req = "https://www.abuseipdb.com/check/{}/json?key={}&days={}".format(uip, api_key, days)
    info = requests.get(req).json()
    # DEBUG print(info)
    if not info:
        # DEBUG print("IF NOT INFO loop\n\n")
        null_logs.append(uip)
    elif type(info) is list:
        log = info[0]
        isWhitelisted = log['isWhitelisted']
        abuseConfidenceScore = int(log['abuseConfidenceScore'])
        # DEBUG print("abuse confidence score is", abuseConfidenceScore," is whitelisted?", isWhitelisted)
        if abuseConfidenceScore == 0:
            null_logs.append(uip)
            #DEBUG print('appended to null')
        elif 0 < abuseConfidenceScore <= 30:
            ITSEC_logs.append(uip)
            # DEBUG print('appended to ITSEC')
        elif 30 < abuseConfidenceScore <= 100:
            NOC_logs.append(uip)
            bIPs.write(uip)
            bIPs.write("\n")
            # DEBUG print('appended to NOC')
        else:
            # DEBUG print('unable to process')
            null_logs.append(uip)
    else:
        # DEBUG print("info type is:", type(info))
        null_logs.append(uip)

def get_latest_file():
    list_of_files = glob.glob('./Log_Files/*')
    latest_file = max(list_of_files, key=os.path.getctime)
    ofile = open(latest_file, "r")
    recent_data = ofile.read()
    ofile.close()
    return(recent_data)

def isolate_ip(data):
    rgx = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    rgxdata = re.findall(rgx, data)
    return (rgxdata)

def main():
    NOC_logs = []
    ITSEC_logs = []
    null_logs = []
    unique_ipaddrs = []
    days = 30
    data = get_latest_file()
    # DEBUG print("obtained lateset file")
    ipaddrs = isolate_ip(data)
    #print ("successfully obtained ip addr:",ipaddrs)
    with open('blockedIPs.txt', 'r') as bIPs:
        xip = [line.strip() for line in bIPs]
    bIPs = open('blockedIPs.txt', 'a+')
    #print(xip)
    for ip in ipaddrs:
        if ip not in xip:
            unique_ipaddrs.append(ip)
    for uip in unique_ipaddrs:
        if ipaddress.ip_address(uip).is_private is False:
            # DEBUG make sure it is not a Qualys IP
            if ipaddress.ip_address(uip) in ipaddress.ip_network('64.39.96.0/20'):
                ITSEC_logs.append(uip)
            else:
                abuseipdb_check(uip, bIPs, days, NOC_logs, ITSEC_logs, null_logs)
    #print("IP addresses appended to NOC:", NOC_logs)
    #print("IP addresses appended to IT SEC:", ITSEC_logs)
    #print("IP addresses returned as null or no information:", null_logs)
    bIPs.close()
    if NOC_logs:
        email_NOC(NOC_logs)
    else:
        print("No logs sent to NOC")
    email_ITSEC(ITSEC_logs, null_logs, NOC_logs)

if __name__ == '__main__':
    main()
