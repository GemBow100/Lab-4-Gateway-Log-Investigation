"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib
import re
import pandas as pd
import os
import csv

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()


    #generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)
    # extract data
    with open('./downloads/gateway.txt', 'r') as f:
        gateway = f.readlines()
    
    ports = csv.reader(f)
    for row in ports:
        date, time, source_ip, destination_ip, source_port, destination_port = row
        if destination_port == destination_port:
            log_analysis_lib = 'gateway.txt'
            destination_port = {}
    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    
# open the folder inorder to extract the data in read mode.
    with open('./downloads/gateway.txt', 'r') as f:
        gateway = f.readlines()
 #Looking for ports in SRC, DST and LEN
    captured_data = ['SRC=(.*?) DST=(.*?) LEN=(.*?)']
    DataFrame.to_dict([captured_data])

    return {}

def generate_port_traffic_report(port_number):

#DPT to be reported in dictonary format.
    dpt_counts={}
#Looking for ports the numbers of DPT ports
    int = ('DPT=(.*?)')
# Get data from records that contain the specified destination port
    with open('./downloads/gateway.txt', 'r') as f:
        gateway = f.readlines()
    for line in gateway:
        print(line)
        for match in re.search(int):
            if match: dpt_counts =match.group(1)
        for dpt in port_number:
            dpt_counts.setdefault(dpt,0)
            dpt_counts[dpt] += 1
        return dpt_counts
    results = generate_port_traffic_report(port_number)
    print( results)
    # Generate the CSV report
    log_analysis_lib.df.to_csv ('generate_port_traffic_report', index= False)
    

def generate_invalid_user_report():
    # Get data from records that show attempted invalid user login
    for port, count in generate_invalid_user_report():
        if count >= 100:
            generate_invalid_user_report(port)
        return count
    with open('./downloads/gateway.txt', 'r') as f:
        gateway = f.readlines()
    
    ports = csv.reader(f)
    for row in ports:
        invalid_users = row
        if invalid_users == invalid_users:
            gateway= 'gateway.txt'
            invalid_users = {}
    # Generate the CSV report
    invalid_users.df.to_csv('generate_invalid_user_report')



def generate_source_ip_log(ip_address):
    ip_address_counts={}
    # Get all records that have the specified sourec IP address
    with open('./downloads/gateway.txt', 'r') as f:
        gateway = f.readlines()
        for row in gateway.csv.reader(f):
            row_source_ip = row
            if row_source_ip == source_ip:
                ip_address_counts.setdefault(ip_address, 0)
                ip_address_counts[ip_address] += 1

    # Save all records to a plain text .log file
    filename=  "source_ip{address}.log"
    with open(filename, 'w') as source_ip:
        source_ip.write(ip_address)


if __name__ == '__main__':
    main()