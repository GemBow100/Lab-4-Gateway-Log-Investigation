"""
Library of functions that are useful for analyzing plain-text log files.
"""
import re
import sys
import os
import pandas as pd

def main():
    # Get the log file path from the command line
    log_path = get_file_path_from_cmd_line()

    # This command will investigate the gateway log by filtering the invalid users using regex.
    filtered_records, _= filter_log_by_regex(log_path, 'pam',print_summary=True, print_records=True)

    # The command below will filter data form the gateway log using regex.
    filtered_records, extracted_data = filter_log_by_regex(log_path, 'SRC=(.*?) DST=(.*?) LEN=(.*?)')
    extracted_df =pd.DataFrame(extracted_data, columns=('Source IP', 'Destination IP', 'Length'))
    extracted_df.to_csv('data.csv', index=False)

    pass

def get_file_path_from_cmd_line(param_num=1):
    
    # Ensures that the command line parameter is present
    if len(sys.argv)< param_num + 1:
        print (f'Error: Missing log file path expected as command line parameter {param_num}.')
        sys.exit (f'Exit Script execution')
    # This command gets a value from the parameters and converts it.
    log_path = os.path.abspath(sys.argv[param_num])
    #The command below checks to see if the file exists.
    if not os.path.isfile(log_path):
        print (f'Error: "{log_path}" is not the path of an exisitng file.')
        sys.exit(f'Exit Script execution')
    return log_path

def filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False):
   
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary is True:
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')

    return (filtered_records, captured_data)

if __name__ == '__main__':
    main()        