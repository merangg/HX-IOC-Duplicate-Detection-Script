import json
import os
from collections import defaultdict, Counter
from datetime import datetime
import chardet
import glob
import socket
from tqdm import tqdm

asciiheader = """
 ██▓ ▒█████   ▄████▄      ▄████▄   ██░ ██ ▓█████  ▄████▄   ██ ▄█▀ ▓█████  ██▀███  
▓██▒▒██▒  ██▒▒██▀ ▀█     ▒██▀ ▀█   ▓██░ ██▒▓█   ▀ ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒██▒▒██░  ██▒▒▓█    ▄    ▒▓█    ▄ ▒██▀▀██░▒███   ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
░██░▒██   ██░▒▓▓▄ ▄██▒   ▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  
░██░░ ████▓▒░▒ ▓███▀ ░   ▒ ▓███▀ ░░▓█▒░██▓░▒████▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
░▓  ░ ▒░▒░▒░ ░ ░▒ ▒  ░   ░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
 ▒ ░  ░ ▒ ▒░   ░  ▒        ░  ▒    ▒ ░▒░ ░ ░ ░  ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
 ▒ ░░ ░ ░ ▒  ░           ░         ░  ░░ ░   ░   ░        ░ ░░ ░    ░     ░░   ░ 
 ░      ░ ░  ░ ░         ░ ░       ░  ░  ░   ░  ░░ ░      ░  ░      ░  ░   ░     
             ░           ░                       ░                               
                                                                    version 1.0.0
"""

def get_user_info():
    username = os.getlogin()  # Get the current logged-in username
    hostname = socket.gethostname()  # Get the system's hostname
    return username, hostname

def update_audit_log(audit_log_path, username, hostname, date_time, new_iocs_count, total_iocs, results_written, repository_path):
    log_entry = (
        f"Date and Time of Execution: {date_time}\n"
        f"Number of new IOCs added to the repository: {new_iocs_count}\n"
        f"Total number of IOCs in the repository: {total_iocs}\n"
        f"Results written to: {', '.join(results_written)}\n"
        f"Repository file updated: {repository_path}\n"
        f"Executed by: {username}\n"
        f"Hostname: {hostname}\n"
        "------------------------------------------\n"
    )

    if not os.path.exists(audit_log_path):
        with open(audit_log_path, 'w') as file:
            file.write("Audit Log\n")
            file.write("==========================================\n")
    
    with open(audit_log_path, 'a') as file:
        file.write(log_entry)

def extract_values_from_json(file_path):
    values = defaultdict(list)
    try:
        if file_path.endswith('.rule'):
            with open(file_path, 'rb') as file:
                raw_data = file.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                
            with open(file_path, 'r', encoding=encoding) as file:
                content = json.load(file)
                
                for key, value in content.items():
                    if isinstance(value, dict):
                        for execution_step in value.get("execution", []):
                            for condition in execution_step:
                                if "value" in condition:
                                    token = condition.get("token")
                                    if token in [
                                        "imageLoadEvent/timeStamp","imageLoadEvent/fullPath","imageLoadEvent/devicePath","imageLoadEvent/drive", "addressNotificationEvent/address",
                                        "imageLoadEvent/filePath","imageLoadEvent/fileName","imageLoadEvent/fileExtension","imageLoadEvent/pid",
                                        "imageLoadEvent/process","imageLoadEvent/parentPid","imageLoadEvent/username","imageLoadEvent/error",
                                        "processEvent/timeStamp","processEvent/eventType","processEvent/processPath","processEvent/process",
                                        "processEvent/parentPid","processEvent/parentProcessPath","processEvent/parentProcess","processEvent/username",
                                        "processEvent/startTime","processEvent/processCmdLine","processEvent/md5","fileWriteEvent/timeStamp",
                                        "fileWriteEvent/fullPath","fileWriteEvent/devicePath","fileWriteEvent/drive","fileWriteEvent/filePath",
                                        "fileWriteEvent/fileExtension","fileWriteEvent/size","fileWriteEvent/md5","fileWriteEvent/pid","fileWriteEvent/process",
                                        "fileWriteEvent/processPath","fileWriteEvent/parentProcessPath","fileWriteEvent/writes","fileWriteEvent/numBytesSeenWritten",
                                        "fileWriteEvent/lowestFileOffset","fileWriteEvent/dataAtLowestOffset","fileWriteEvent/textAtLowestOffset",
                                        "fileWriteEvent/closed","fileWriteEvent/error","fileWriteEvent/username","regKeyEvent/timeStamp","regKeyEvent/path",
                                        "regKeyEvent/hive","regKeyEvent/keyPath","regKeyEvent/eventType","regKeyEvent/valueName","regKeyEvent/valueType",
                                        "regKeyEvent/value","regKeyEvent/username","regKeyEvent/originalPath","regKeyEvent/process","regKeyEvent/processPath",
                                        "regKeyEvent/pid","regKeyEvent/text","dnsLookupEvent/timeStamp","dnsLookupEvent/hostname","dnsLookupEvent/pid",
                                        "dnsLookupEvent/process","dnsLookupEvent/processPath","dnsLookupEvent/username","ipv4NetworkEvent/timeStamp",
                                        "ipv4NetworkEvent/remoteIP","ipv4NetworkEvent/remotePort","ipv4NetworkEvent/localIP","ipv4NetworkEvent/localPort",
                                        "ipv4NetworkEvent/protocol","ipv4NetworkEvent/pid","ipv4NetworkEvent/username","ipv4NetworkEvent/processPath",
                                        "ipv4NetworkEvent/process","urlMonitoringEvent/timeStamp","urlMonitoringEvent/hostname","urlMonitoringEvent/requestUrl",
                                        "urlMonitoringEvent/urlMethod","urlMonitoringEvent/userAgent","urlMonitoringEvent/httpHeader","urlMonitoringEvent/remoteIpAddress",
                                        "urlMonitoringEvent/remotePort","urlMonitoringEvent/localPort","urlMonitoringEvent/pid","urlMonitoringEvent/process",
                                        "urlMonitoringEvent/processPath","urlMonitoringEvent/username","urlMonitoringEvent/error","addressNotificationEvent/timeStamp"
                                    ]:
                                        values[token].append((condition["value"], file_path))
        else:
            raise ValueError("Error: Only .rule files are allowed.")
    except (json.JSONDecodeError, FileNotFoundError) as e:
        pass  # Handle the exception silently for production
    return values

def find_duplicates(values):
    duplicates = defaultdict(list)
    for token, vals in values.items():
        counts = Counter(val[0] for val in vals)
        for val, count in counts.items():
            if count > 1:
                file_list = [file for value, file in vals if value == val]
                duplicates[token].append((val, count, file_list))
    return duplicates

def get_directory_info(directories):
    directory_info = {}
    for directory in directories:
        total_size = 0
        num_files = 0
        for filename in os.listdir(directory):
            if filename.endswith('.rule'):
                num_files += 1
                file_path = os.path.join(directory, filename)
                total_size += os.path.getsize(file_path)
        directory_info[directory] = {
            "number_of_files": num_files,
            "total_size": total_size / (1024 * 1024)  # Convert size to MB
        }
    return directory_info

def write_extracted_values(values, output_path, directory_info):
    extracted_values = {token: Counter(val[0] for val in vals) for token, vals in values.items()}
    result = {
        "directories": directory_info,
        "timestamp": datetime.now().isoformat(),
        "number_of_extracted_values": sum(len(vals) for vals in values.values()),
        "extracted_values": extracted_values
    }
    with open(output_path, 'w') as file:
        json.dump(result, file, indent=4)

def write_duplicates(duplicates, output_path):
    with open(output_path, 'w') as file:
        file.write("Duplicate values:\n")
        for token, dups in duplicates.items():
            if dups:
                for dup, count, files in dups:
                    file.write(f"\n{token}: {dup} (Count: {count})\n\n")
                    file.write("Found in files:\n")
                    for i, file_path in enumerate(files, 1):
                        if isinstance(file_path, tuple):  # Check if the file path includes [REPO] tag
                            tag, file_location = file_path
                            file.write(f"{i}. {tag} {file_location}\n")
                        else:
                            file.write(f"{i}. {file_path}\n")

def store_values_in_repository(values, repository_path):
    repository_data = defaultdict(list)
    new_iocs_count = 0
    duplicates_in_repository = defaultdict(list)

    # Load existing repository data if it exists
    if os.path.exists(repository_path):
        try:
            with open(repository_path, 'r') as file:
                repository_data = json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            pass  # Handle the exception silently for production
    
    # Add new values to the repository, checking for duplicates in the repository
    for token, vals in values.items():
        for value, file_path in vals:
            if value in repository_data.get(token, []):  # If the value exists in repository
                duplicates_in_repository[token].append((value, "[REPO]", file_path))
            else:
                repository_data[token].append(value)
                new_iocs_count += 1
    
    try:
        with open(repository_path, 'w') as file:
            json.dump(repository_data, file, indent=4)
    except (json.JSONDecodeError, FileNotFoundError):
        pass  # Handle the exception silently for production
    
    return new_iocs_count, len(repository_data), duplicates_in_repository

def main():
    print(asciiheader)
    
    directories = input("Enter the directories to scan (comma-separated, wildcards allowed): ").split(",")
    directories = [directory.strip() for directory in directories]
    
    expanded_directories = []
    for directory in directories:
        expanded_directories.extend(glob.glob(os.path.join(directory, '**', '*.rule'), recursive=True))

    extracted_values = defaultdict(list)
    for directory in tqdm(expanded_directories, desc="Scanning directories"):  # Progress bar for directories
        file_values = extract_values_from_json(directory)
        for key, vals in file_values.items():
            extracted_values[key].extend(vals)
    
    duplicates = find_duplicates(extracted_values)
    
    directory_info = get_directory_info(directories)
    output_directory = input("Enter the directory to save the results: ")
    
    output_file_path = os.path.join(output_directory, "extracted_values.json")
    current_date = datetime.now().strftime('%Y-%m-%d')
    output_file_path_duplicates = os.path.join(output_directory, f"duplicates_{current_date}.txt")
    results_written = ["extracted_values.json", f"duplicates_{current_date}.txt"]

    write_extracted_values(extracted_values, output_file_path, directory_info)
    write_duplicates(duplicates, output_file_path_duplicates)

    repository_path = os.path.join(output_directory, "repository.json")

    if duplicates_in_repository:
        for token, dups in duplicates_in_repository.items():
            for dup, file_path in dups:
                pass 
             
    audit_log_path = os.path.join(output_directory, "audit_log.txt")
    username, hostname = get_user_info()
    current_date_time = datetime.now().isoformat()
    
    update_audit_log(audit_log_path, username, hostname, current_date_time, new_iocs_count, current_repo_size, results_written, repository_path)
    
    print(f"Extraction completed. Results saved to '{output_directory}'.")
    print(f"Total number of new IOCs: {new_iocs_count}")

if __name__ == "__main__":
    main()
