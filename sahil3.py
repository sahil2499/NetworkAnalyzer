from datetime import timedelta
import datetime
import re
import subprocess
import numpy as np
import string
import pyshark
import socket
from scapy.all import *
from collections import defaultdict
from collections import defaultdict
import time
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
import subprocess
previous_timestamp = None  
connection_data = {}  
urgent_packets_count = 0  
processed_data={}
def process_packet(packet):
    global previous_timestamp, connection_data, urgent_packets_count
    global processed_data
    try:
        
        if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and hasattr(packet, 'length'):
            
            timestamp = float(packet.sniff_timestamp)
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            protocol = packet.transport_layer
            length = int(packet.length)
            Land=calculate_land(packet)
            count_of_connections=count_connections_to_destination(packet)
            Root_shell = detect_root_shell14(packet)
            detect_logins_guest=detect_guest_login(packet)
            
            destination_service = extract_destination_service(packet)
            Num_Ftp_Commands=calculate_outbound_ftp_commands(packet)
            
            flags = extract_flags(packet)
            SrvError_rate=calculate_Serviceserror_rate(packet)
            file_access=detect_file_access(packet)
            count_connection_port=count_connections_to_service(packet)
            
            source_bytes = extract_source_bytes(packet)
            destination_bytes = extract_destination_bytes(packet)
            shell_prompts=detect_shell_prompt(packet)
            Num_file_creation=detect_file_creation(packet)
            is_hot_login_value=detect_hot_login(packet)
            serror_rate=calculate_derror_rate(packet)
            Rerror_rate=valid_Rerror_packets(packet)
            Srv_error_withREJ=count_connections_with_rej_flag_with_same_port(packet)
            Same_srv_rate=calculate_same_srv_rate(packet)
            Diff_srv_rate=calculate_diff_srv_rate(packet)
            Srv_diff_host_rate=calculate_percentage_of_different_destination_addresses(packet)
            Dst_host_count=calculate_num_connections_same_destination_host(packet)
            Dst_host_srv_count=update_port_count(packet)
            Dst_host_same_srv_rate=calculate_percentage_same_service_connections(packet)
            Dst_host_diffsrv_rate=calculate_percentage_diff_service_connections(packet)
            Dst_host_samesrc_port_rate=calculate_dst_host_same_src_port(packet)
            dst_host_srvdiff_host_rate=calculate_Dst_host_srvdiff_host_rate(packet)
            Calculate_Dst_host_serror_ratef=calculate_Dst_host_serror_rate(packet)
            Dst_host_srv_serror_rate=Dst_host_srv_serror_ratef(packet)
            Dst_host_rerror_rate=calculate_Dst_host_rerror_rate(packet)
            Dst_host_srv_rerror_rate=calculate_percentage_same_src_port(packet)
            # Extract Wrong_fragment count
            Wrong_fragment = extract_wrong_fragment(packet)
            Su_attempted = detect_root_shell15(packet)
            # Check if the urgent bit is activated
            if 'tcp' in packet and packet.tcp.flags_urg == '1':
                urgent_packets_count += 1

            # Extract Num_failed_logins count
            Num_root=calculate_num_root(packet)
            Hot=calculate_hot(packet)
            Num_failed_logins = extract_failed_logins(packet)
            login_status = extract_login_status(packet)
            Num_compromise = Num_compromised(packet)
            # Calculate duration based on timestamp difference
            duration = timestamp - previous_timestamp if previous_timestamp is not None else 0
            previous_timestamp = timestamp

            # Update or initialize connection data
            connection_key = f"{source_ip}:{destination_ip}:{protocol}"
            if connection_key in connection_data:
                connection_data[connection_key]['source_bytes'] += source_bytes
                connection_data[connection_key]['destination_bytes'] += destination_bytes
                connection_data[connection_key]['wrong_fragment'] += Wrong_fragment
                
                if 'num_failed_logins' not in connection_data[connection_key]:
                    connection_data[connection_key]['num_failed_logins'] = 0
                connection_data[connection_key]['num_failed_logins'] += Num_failed_logins
            else:
                connection_data[connection_key] = {
                    'source_bytes': source_bytes,
                    'destination_bytes': destination_bytes,
                    'wrong_fragment': Wrong_fragment,
                    'num_failed_logins': Num_failed_logins
                }

            processed_data ={'duration': duration,
            
            
            'protocol': protocol,
            'service': destination_service,
            
            'flag': flags,
            'src_bytes': source_bytes,
            'dst_bytes': destination_bytes,
            'land': Land,
            'wrong_fragment': Wrong_fragment,
            'urgent': urgent_packets_count,
            'hot':Hot,
            'num_failed_logins': Num_failed_logins,
            'logged_in': login_status,
            'num_compromised': Num_compromise,
            
            'root_shell': Root_shell,
            'su_attempted': Su_attempted,
            'num_root':Num_root,
            'num_file_creations': Num_file_creation,
            'num_shells': shell_prompts,
            'num_access_files': file_access,
            'num_outbound_cmds': Num_Ftp_Commands,
            'is_host_login': is_hot_login_value,
            'is_guest_login': detect_logins_guest,
            'count': count_of_connections,
            'srv_count': count_connection_port,
            'serror_rate': serror_rate,
            'srv_serror_rate': SrvError_rate,
            'rerror_rate': Rerror_rate,
            'srv_rerror_rate': Srv_error_withREJ,
            'same_srv_rate': Same_srv_rate,
            'diff_srv_rate': Diff_srv_rate,
            'srv_diff_host_rate': Srv_diff_host_rate,
            'dst_host_count': Dst_host_count,
            'dst_host_srv_count': Dst_host_srv_count,
            'dst_host_same_srv_rate': Dst_host_same_srv_rate,
            'dst_host_diff_srv_rate': Dst_host_diffsrv_rate,
            'dst_host_same_src_port_rate': Dst_host_samesrc_port_rate,
            'dst_host_srv_diff_host_rate': calculate_Dst_host_srvdiff_host_rate(packet),
            'dst_host_serror_rate': Calculate_Dst_host_serror_ratef,
            'dst_host_srv_serror_rate': Dst_host_srv_serror_rate,
            'dst_host_rerror_rate': Dst_host_rerror_rate,
            'dst_host_srv_rerror_rate': Dst_host_srv_rerror_rate
            
            
            
            }
            return processed_data

        
    except AttributeError as e:
        # Ignore packets without the necessary attributes
        return None
#num_root
def calculate_num_root(packet):
    root_shell_patterns = [
        re.compile(r'\bsudo\b', re.IGNORECASE),
        re.compile(r'\bsu\b', re.IGNORECASE),
        # Add more patterns as needed
    ]

    # Check for each pattern in the packet
    for pattern in root_shell_patterns:
        if pattern.search(str(packet)):
            print(f"Root Shell Condition Detected in Packet:\n{packet}")
            return 1

    return 0
    
#hot

import re

def calculate_hot(packet):
    try:
        # Check if the packet is an HTTP packet
        if 'HTTP' in packet:
            http_payload = str(packet['HTTP'])
            
            hot_patterns = [
                r'entering\s+a\ssystem\sdirectory',
                r'creating\s+programs',
                r'executing\s+programs'
            ]
            
            hot_count = 0
            
            # Search for each hot pattern in the HTTP payload
            for pattern in hot_patterns:
                if re.search(pattern, http_payload, re.IGNORECASE):
                    hot_count += 1
                    
            return hot_count
        else:
            return 0
    except Exception as e:
        print(f"Error processing packet: {e}")
        return 0

#Land 
def calculate_land(packet):
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport
        
        if src_ip == dst_ip and src_port == dst_port:
            return 1
        else:
            return 0
    except AttributeError:
        return 0  



#41



port_count_dict41 = {}

# Set of specified flags
specified_flags41 = {'0x0004'}

def calculate_percentage_same_src_port(packet):
    global port_count_dict41

    if 'TCP' in packet and 'IP' in packet:
        # Extract source port
        src_port = packet.tcp.srcport

        if src_port in port_count_dict41:
            port_count_dict41[src_port][0] += 1
        else:
            port_count_dict41[src_port] = [1, 0]

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and packet.tcp.flags:
            flags_hex = packet.tcp.flags
            if flags_hex in specified_flags41:
                port_count_dict41[src_port][1] += 1

        total_connections = sum(count[0] for count in port_count_dict41.values())

        # Calculate the percentage for each source port
        percentage_same_src_port = (port_count_dict41[src_port][1] / total_connections) 
        return round(percentage_same_src_port,2)
    else:
        return 0


#40
ip_count_dict40 = {}

# Set of specified flags
specified_flags = {'0x0004'}

def calculate_Dst_host_rerror_rate(packet):
    global ip_count_dict40

    if 'IP' in packet:
        src_ip = packet.ip.src

        if src_ip in ip_count_dict40:
            ip_count_dict40[src_ip][0] += 1
        else:
            ip_count_dict40[src_ip] = [1, 0]

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and packet.tcp.flags:
            flags_hex = packet.tcp.flags
            if flags_hex == '0x0004':
                ip_count_dict40[src_ip][1] += 1

        for ip, counts in ip_count_dict40.items():
            total_connections = counts[0]
            flag_triggers = counts[1]
            if total_connections > 0:
                percentage_flag_connections = (flag_triggers / total_connections) 
                return percentage_flag_connections
        else:
            return 0



#39
port_count_dict1 = {}

# Set of specified flags
specified_flags = {'0x0018', '0x0002', '0x0004', '0x0008', '0x0011'}

def Dst_host_srv_serror_ratef(packet):
    global port_count_dict1

    if 'TCP' in packet and hasattr(packet.tcp, 'srcport'):
        src_port = packet.tcp.srcport

        if src_port in port_count_dict1:
            port_count_dict1[src_port][0] += 1
        else:
            port_count_dict1[src_port] = [1, 0]

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and packet.tcp.flags:
            flags_hex = packet.tcp.flags
            if flags_hex in specified_flags:
                port_count_dict1[src_port][1] += 1

        for port, counts in port_count_dict1.items():
            total_connections = counts[0]
            flag_triggers = counts[1]
            if total_connections > 0:
                percentage_flag_connections = (flag_triggers / total_connections) 
                return percentage_flag_connections

    else:
        return 0



#38
ip_count_dict = {}

# Set of specified flags
specified_flags = {'0x0018', '0x0002', '0x0004', '0x0008', '0x0011'}

def calculate_Dst_host_serror_rate(packet):
    global ip_count_dict

    if 'IP' in packet:
        src_ip = packet.ip.src

        if src_ip in ip_count_dict:
            ip_count_dict[src_ip][0] += 1
        else:
            ip_count_dict[src_ip] = [1, 0]

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and packet.tcp.flags:
            flags_hex = packet.tcp.flags
            if flags_hex in specified_flags:
                ip_count_dict[src_ip][1] += 1

        for ip, counts in ip_count_dict.items():
            total_connections = counts[0]
            flag_triggers = counts[1]
            if total_connections > 0:
                percentage_flag_connections = (flag_triggers / total_connections) 
                return round(percentage_flag_connections,2)
        else:
            return 0



#37


port_count_sd = {}
def calculate_Dst_host_srvdiff_host_rate(packet):
    global port_count_sd

    if hasattr(packet, 'transport_layer') and packet.transport_layer:
        src_port = packet[packet.transport_layer].srcport

        port_count_sd[src_port] = port_count_sd.get(src_port, 0) + 1

        total_connections = sum(port_count_ss.values())

        current_count = port_count_sd[src_port]

        if total_connections > 0:
            percentage_same_source_port = round(((total_connections-current_count) / total_connections) , 2)
        else:
            percentage_same_source_port = 0.00  # Round to 2 decimal places even if total_connections is 0

        return (percentage_same_source_port)

    else:
        return 0  # Round to 2 decimal places


#36
port_count_ss = {}
def calculate_dst_host_same_src_port(packet):
    global port_count_ss

    if hasattr(packet, 'transport_layer') and packet.transport_layer:
        # Extract source port
        src_port = packet[packet.transport_layer].srcport

        port_count_ss[src_port] = port_count_ss.get(src_port, 0) + 1

        total_connections = sum(port_count_ss.values())

        current_count = port_count_ss[src_port]

        if total_connections > 0:
            percentage_same_source_port = round((current_count / total_connections) , 2)
        else:
            percentage_same_source_port = 0.00  # Round to 2 decimal places even if total_connections is 0

        return (percentage_same_source_port)

    else:
        return 0  


#35
host_ip_countd = {}

host_ip_service_countd = {}

def calculate_percentage_diff_service_connections(packet):
    global host_ip_countd, host_ip_service_countd

    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer'):
        dst_ip = packet.ip.dst
        service = packet.transport_layer

        host_ip_countd[dst_ip] = host_ip_countd.get(dst_ip, 0) + 1

        if dst_ip not in host_ip_service_countd:
            host_ip_service_countd[dst_ip] = {}
        host_ip_service_countd[dst_ip][service] = host_ip_service_countd[dst_ip].get(service, 0) + 1

        for dst_ip, service_counts in host_ip_service_countd.items():
            total_connections = host_ip_countd[dst_ip]
            same_service_connections = service_counts.get(packet.transport_layer, 0)
            diff_service=total_connections-same_service_connections  # Connections with the same service
            percentage_same_service = (diff_service / total_connections) 
            return percentage_same_service
    else:
        return 0

#34

host_ip_count = {}

host_ip_service_count = {}

def calculate_percentage_same_service_connections(packet):
    global host_ip_count, host_ip_service_count

    # Check if the packet has the necessary features
    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer'):
        dst_ip = packet.ip.dst
        service = packet.transport_layer

        host_ip_count[dst_ip] = host_ip_count.get(dst_ip, 0) + 1

        if dst_ip not in host_ip_service_count:
            host_ip_service_count[dst_ip] = {}
        host_ip_service_count[dst_ip][service] = host_ip_service_count[dst_ip].get(service, 0) + 1

        for dst_ip, service_counts in host_ip_service_count.items():
            total_connections = host_ip_count[dst_ip]
            same_service_connections = service_counts.get(packet.transport_layer, 0)  # Connections with the same service
            percentage_same_service = (same_service_connections / total_connections) 
            return percentage_same_service
    else:
        return 0



# 33
port_count = {}

def update_port_count(packet):
    global port_count

    if hasattr(packet, 'transport_layer') and packet.transport_layer:
        # Extract destination port
        dst_port = packet[packet.transport_layer].dstport

        port_count[dst_port] = port_count.get(dst_port, 0) + 1

        return (port_count[dst_port])

    else:
        return 0


#Number 32
MAX_CONNECTIONS = 255
destination_hosts_count = {}

def calculate_num_connections_same_destination_host(packet):
    global destination_hosts_count

    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer'):
        # Extract destination IP address
        dst_ip = packet.ip.dst

        destination_hosts_count[dst_ip] = min(destination_hosts_count.get(dst_ip, 0) + 1, MAX_CONNECTIONS)

        num_connections_same_destination_host = destination_hosts_count[dst_ip]
        
        return num_connections_same_destination_host

    return 0  


#Number 31
previous_connections_data31 = {}

def calculate_percentage_of_different_destination_addresses(packet):
    global previous_connections_data31

    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and packet.transport_layer is not None and hasattr(packet[packet.transport_layer], 'dstport'):
        # Extract information from the packet
        timestamp = float(packet.sniff_timestamp)
        dst_port = packet[packet.transport_layer].dstport

        window_start_time = timestamp - 2

        destination_addresses = previous_connections_data31.get(dst_port, set())

        previous_connections_within_window = [
            conn for conn in destination_addresses
            if conn[0] >= window_start_time
        ]

        destination_addresses.add((timestamp, packet.ip.dst))

        # Update the dictionary entry
        previous_connections_data31[dst_port] = destination_addresses

        total_connections_to_port = len(previous_connections_within_window)
        num_different_destination_addresses = len(set(addr[1] for addr in previous_connections_within_window))
        
        if total_connections_to_port != 0:
            percentage = (num_different_destination_addresses / total_connections_to_port)
            return (round(percentage, 2))
        else:
            return 0  

    return 0  


#Number 30 
previous_connections_data1 = {}
def calculate_diff_srv_rate(packet):
    global previous_connections_data

    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and packet.transport_layer is not None and hasattr(packet, 'length'):
        timestamp = float(packet.sniff_timestamp)

        if hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            window_start_time = timestamp - 2

            previous_connections_list = previous_connections_data1.get(dst_ip, [])

            previous_connections_within_window = [
                conn for conn in previous_connections_list
                if conn['timestamp'] >= window_start_time and conn['service'] != get_destination_service_helper(packet)
            ]

            num_connections_to_service = len(previous_connections_within_window)
            total_connections_to_host = len(previous_connections_list)

            previous_connections_list.append({'timestamp': timestamp, 'service': get_destination_service_helper(packet)})

            previous_connections_data1[dst_ip] = previous_connections_list

            if total_connections_to_host != 0:
                percentage = (num_connections_to_service / total_connections_to_host)
                percentage=round(percentage,2)
            else:
                percentage = 0

            return percentage

#number 29 
previous_connections_data = {}

def calculate_same_srv_rate(packet):
    global previous_connections_data

    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and packet.transport_layer is not None and hasattr(packet, 'length'):
        timestamp = float(packet.sniff_timestamp)

        if hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            window_start_time = timestamp - 2

            previous_connections_list = previous_connections_data.get(dst_ip, [])

            previous_connections_within_window = [
                conn for conn in previous_connections_list
                if conn['timestamp'] >= window_start_time and conn['service'] == get_destination_service_helper(packet)
            ]

            num_connections_to_service = len(previous_connections_within_window)
            total_connections_to_host = len(previous_connections_list)

            previous_connections_list.append({'timestamp': timestamp, 'service': get_destination_service_helper(packet)})

            previous_connections_data[dst_ip] = previous_connections_list

            if total_connections_to_host != 0:
                percentage = (num_connections_to_service / total_connections_to_host)
                percentage=round(percentage,2)
            else:
                percentage = 0

            return percentage
def get_destination_service_helper(packet):
   
    if hasattr(packet, 'transport_layer') and packet.transport_layer is not None and hasattr(packet[packet.transport_layer], 'dstport'):
        return packet[packet.transport_layer].dstport
    else:
        return None


previous_connections_with_rej={}
def count_connections_with_rej_flag_with_same_port (packet):
    global previous_connections_with_rej

    if hasattr(packet, 'transport_layer') and packet.transport_layer is not None and hasattr(packet, 'length'):
       
        timestamp = float(packet.sniff_timestamp)

      
        if hasattr(packet[packet.transport_layer], 'dstport'):
            destination_port = packet[packet.transport_layer].dstport

            window_start_time = timestamp - 2

            previous_connections_list = previous_connections_with_rej.get(destination_port, [])

            previous_service_connections_with_rej = [
                (conn, rej_flag) for conn, rej_flag in previous_connections_list if conn >= window_start_time and rej_flag
            ]

            num_connections_with_rej = len(previous_service_connections_with_rej)

       
            previous_connections_list.append((timestamp, is_rej_flag_set(packet)))

            previous_connections_with_rej[destination_port] = previous_connections_list
            num1=count_connections_to_service(packet)
            if num1!=0:
                return num_connections_with_rej/num1
            else:
                return 0
            

def is_rej_flag_set(packet):
    
    if 'TCP' in packet:
        tcp_flags = int(packet.tcp.flags, 16)
        return (tcp_flags & 0x04) != 0  
    else:
        return False  


def get_validated_Rerror_connections(packet, connection_info, time_period=2):
    validated_connections = []

    
    if 'IP' in packet and 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

            key = (src_ip, src_port, dst_ip, dst_port)

            if key in connection_info:
                last_timestamp, rej_flag = connection_info[key]

                if datetime.now() - last_timestamp <= timedelta(seconds=time_period):
                    if src_ip == key[2] and src_port == key[3]:
                        connection_info[key] = (datetime.now(), rej_flag)

                    if rej_flag:
                        validated_connections.append(key)

                else:
                    del connection_info[key]

            else:
                connection_info[key] = (datetime.now(), False)
    
    
    num2 = len(validated_connections)
    num1=count_connections_to_service(packet)
    if num1 !=0:
        return num2/num1
    else:
        return 0


connection_info = {}

def valid_Rerror_packets(packet):
    global connection_info

    validated_percentage = get_validated_Rerror_connections(packet, connection_info,time_period=2)
    return validated_percentage


def calculate_Serviceserror_rate(packet):
    global previous_connections

    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and hasattr(packet, 'length'):
        timestamp = float(packet.sniff_timestamp)
        destination_ip = packet.ip.dst
        protocol = packet.transport_layer

        num_connections_to_destination = count_connections_to_service(packet)
        serror_connections_count = 0
        
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and packet.tcp.flags:
            flags_hex = packet.tcp.flags
            if flags_hex == '0x0018' or flags_hex == '0x0002' or flags_hex == '0x0004' or flags_hex == '0x0008'  or flags_hex == '0x0011':
                serror_connections_count += 1
                print(serror_connections_count)
        #
            serror_rate = ((serror_connections_count / num_connections_to_destination) ) if num_connections_to_destination > 0 else 0
        
        return round(serror_rate, 2)


def calculate_derror_rate(packet):
    global previous_connections

    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and hasattr(packet, 'length'):
        timestamp = float(packet.sniff_timestamp)
        destination_ip = packet.ip.dst
        protocol = packet.transport_layer

        num_connections_to_destination = count_connections_to_destination(packet)
        serror_connections_count = 0
        
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and packet.tcp.flags:
            flags_hex = packet.tcp.flags
            if flags_hex == '0x0018' or flags_hex == '0x0002' or flags_hex == '0x0004' or flags_hex == '0x0008'  or flags_hex == '0x0011':
                serror_connections_count += 1
                print(serror_connections_count)
        
            serror_rate = ((serror_connections_count / num_connections_to_destination) ) if num_connections_to_destination > 0 else 0
        
        return round(serror_rate, 2)


def detect_guest_login(packet):
    try:
        if 'LOGIN' in packet:
            login_info = packet.LOGIN
            username = login_info.get('username', '').lower()

            guest_logins = ['guest', 'visitor', 'demo', 'testuser', 'public']

            is_guest_login_value = 1 if username in guest_logins else 0

            return is_guest_login_value

    except AttributeError as e:
        print(f"Error processing packet: {e}")

    return 0  

previous_connections = defaultdict(list)


def count_connections_to_service(packet):
    global previous_connections

    if hasattr(packet, 'transport_layer') and hasattr(packet, 'length'):
        # Extract information from the packet
        timestamp = float(packet.sniff_timestamp)
        destination_port = packet[packet.transport_layer].dstport

        window_start_time = timestamp - 2

        previous_service_connections = [
            conn for conn in previous_connections[destination_port] if conn >= window_start_time
        ]

        num_connections_to_service = len(previous_service_connections)

        previous_connections[destination_port].append(timestamp)

        return num_connections_to_service

previous_connections = defaultdict(list)

def count_connections_to_destination(packet):
    global previous_connections

    
        # Check if the packet has necessary features
    if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and hasattr(packet, 'length'):
            timestamp = float(packet.sniff_timestamp)
            destination_ip = packet.ip.dst
            protocol = packet.transport_layer

            window_start_time = timestamp - 2

            previous_destination_connections = [
                conn for conn in previous_connections[destination_ip] if conn >= window_start_time
            ]

            num_connections_to_destination = len(previous_destination_connections)

            previous_connections[destination_ip].append(timestamp)

            return num_connections_to_destination


def detect_hot_login(packet):
    is_hot_login_value=0
    if 'LOGIN' in packet:
            login_info = packet.LOGIN
            username = login_info.get('username', '').lower()

            hot_logins = ['root', 'admin']

            is_hot_login_value = 1 if username in hot_logins else 0

            return is_hot_login_value
    return is_hot_login_value



def calculate_outbound_ftp_commands(packet):
    num_outbound_commands = 0
    
    if 'FTP' in packet:
        ftp_data = packet.ftp
        if hasattr(ftp_data, 'request_command') and ftp_data.request_command:
            ftp_command_pattern = re.compile(r'\b(?:USER|PASS|CWD|PASV|LIST|RETR|STOR|QUIT)\b', re.IGNORECASE)
            
            for pattern in ftp_command_pattern:
                if pattern.search(str(ftp_data.request_command)):
                    print(f"Outbound FTP Command Detected in FTP Packet:\n{packet}")
                    num_outbound_commands += 1

    return num_outbound_commands

def detect_file_access(packet):
    num_file_access=0

    file_access_patterns = [
        re.compile(r'\bopen\(', re.IGNORECASE),  
        re.compile(r'\bread\(', re.IGNORECASE), 
        re.compile(r'\bwrite\(', re.IGNORECASE),  
        re.compile(r'\bfile\s*=\s*open\(', re.IGNORECASE),  
        re.compile(r'\bwith\s*open\(', re.IGNORECASE),  
        re.compile(r'\bos\.makedirs\(', re.IGNORECASE), 
        re.compile(r'\bshutil\.copy\(', re.IGNORECASE),  
        re.compile(r'\bshutil\.copy2\(', re.IGNORECASE),  
        re.compile(r'\bshutil\.move\(', re.IGNORECASE),  
        re.compile(r'\bos\.system\(', re.IGNORECASE),  
        re.compile(r'\bos\.popen\(', re.IGNORECASE),  
        re.compile(r'\bsubprocess\.call\(', re.IGNORECASE),  
        re.compile(r'\bsubprocess\.run\(', re.IGNORECASE),  
        
    ]

    for pattern in file_access_patterns:
        if pattern.search(str(packet)):
            print(f"File Access Operation Detected in Packet:\n{packet}")
            num_file_access += 1

    return num_file_access


def detect_shell_prompt(packet):
    num_shell_prompts=0

    shell_prompt_patterns = [
        re.compile(r'\$'),  # D
        re.compile(r'\b(?:sh|bash|zsh|fish)\b', re.IGNORECASE),  # Shell names
        re.compile(r'\b(?:terminal|console|command prompt)\b', re.IGNORECASE),  
        re.compile(r'\b(?:cmd\.exe|powershell)\b', re.IGNORECASE),  # Windows command prompt and PowerShell
        re.compile(r'\b(?:[>#~$]|% |>\s|sh-[\d.]+#)\s*$'),  
        re.compile(r'\b(?:user@|admin@|root@)\S+\s*[$#]'),  # User or admin prompts
        re.compile(r'\b(?:>[^>]+|sh:|bash:)\s*$'),  
        
    ]

    for pattern in shell_prompt_patterns:
        if pattern.search(str(packet)):
            print(f"Shell Prompt Detected in Packet:\n{packet}")
            num_shell_prompts += 1

    return num_shell_prompts



def detect_file_creation(packet):
    num_file_creations=0

    file_creation_patterns = [
        re.compile(r'\bopen\(\s*.*?O_CREAT\b', re.IGNORECASE),  
        re.compile(r'\bcreat\(', re.IGNORECASE),  
        re.compile(r'\bwrite\(\s*.*?O_CREAT\b', re.IGNORECASE), 
        re.compile(r'\bfile\s*=\s*open\(', re.IGNORECASE),
        re.compile(r'\bos\.makedirs\(', re.IGNORECASE),  
        re.compile(r'\bshutil\.copy\(', re.IGNORECASE),  
        re.compile(r'\bshutil\.copy2\(', re.IGNORECASE),  
        re.compile(r'\bshutil\.move\(', re.IGNORECASE), 
        re.compile(r'\bos\.system\(', re.IGNORECASE), 
        re.compile(r'\bos\.popen\(', re.IGNORECASE),  
        re.compile(r'\bsubprocess\.call\(', re.IGNORECASE),  
        re.compile(r'\bsubprocess\.run\(', re.IGNORECASE), 
        
    ]

    for pattern in file_creation_patterns:
        if pattern.search(str(packet)):
            print(f"File Creation Operation Detected in Packet:\n{packet}")
            num_file_creations += 1
    return num_file_creations

def detect_root_shell_sudo(packet):
    global num_root_accesses

    root_shell_patterns = [
        re.compile(r'\bsudo\b', re.IGNORECASE),
        re.compile(r'\bsu\b', re.IGNORECASE),
        re.compile(r'\broot\b', re.IGNORECASE),
        re.compile(r'\blogin\b', re.IGNORECASE),
        re.compile(r'\b/etc/passwd\b', re.IGNORECASE), 
        re.compile(r'\b/etc/shadow\b', re.IGNORECASE), 
        re.compile(r'\bpam_tally2\b', re.IGNORECASE),   
        re.compile(r'\b/bin/bash\b', re.IGNORECASE),    
       
    ]

    for pattern in root_shell_patterns:
        if pattern.search(str(packet)):
            print(f"Root Shell Condition sudo Detected in Packet:\n{packet}")
            num_root_accesses += 1


def detect_root_shell14(packet):
    root_shell_patterns = [
        re.compile(r'\bsudo\b', re.IGNORECASE),
        re.compile(r'\bsu\b', re.IGNORECASE),
        re.compile(r'\broot\b', re.IGNORECASE),
        re.compile(r'\bshell\b', re.IGNORECASE),
        re.compile(r'\bec2-user\b', re.IGNORECASE),  # Example: AWS EC2 user
        re.compile(r'\b/bin/sh\b', re.IGNORECASE),
        re.compile(r'\b/bin/bash\b', re.IGNORECASE),
        re.compile(r'\b/etc/passwd\b', re.IGNORECASE),
        re.compile(r'\b/etc/shadow\b', re.IGNORECASE),
        re.compile(r'\b/etc/sudoers\b', re.IGNORECASE),
        re.compile(r'\bpam_tally2\b', re.IGNORECASE),
        re.compile(r'\b/bin/su\b', re.IGNORECASE),
        re.compile(r'\b/etc/security/opasswd\b', re.IGNORECASE),
        re.compile(r'\b/etc/login.defs\b', re.IGNORECASE),
        re.compile(r'\b/etc/security/pwquality\b', re.IGNORECASE),
        re.compile(r'\b/etc/security/user\b', re.IGNORECASE),
        re.compile(r'\b/etc/security/environ\b', re.IGNORECASE),
    ]

    for pattern in root_shell_patterns:
        if pattern.search(str(packet)):
            print(f"Root Shell Condition Detected in Packet:\n{packet}")
            return 1  # Root shell detected

    return 0  # No root shell detected
def detect_root_shell15(packet):
    root_shell_patterns = [
        re.compile(r'\bsudo\b', re.IGNORECASE),
        re.compile(r'\bsu\b', re.IGNORECASE),
    ]

    # Check for each pattern in the packet
    for pattern in root_shell_patterns:
        if pattern.search(str(packet)):
            print(f"Root Shell Condition Detected in Packet:\n{packet}")
            return 1

    return 0

def Num_compromised(packet):
    compromised_patterns = [
        re.compile(r'\b(?:root_shell|root access)\b', re.IGNORECASE),
        re.compile(r'\b(?:su_attempted)\b', re.IGNORECASE),
    ]

    # Check for each pattern in the packet
    for pattern in compromised_patterns:
        if pattern.search(str(packet)):
            print(f"Compromised Condition Detected in Packet:\n{packet}")
            return 1  # Detected compromised condition

    return 0  


def extract_login_status(packet):
    try:
        if 'HTTP' in packet:
            payload_content = str(packet.http)
            
            # You may need to customize these conditions based on your specific use case
            login_patterns = [
                re.compile(r'\b(?:POST|GET)\b.*\b(?:login|auth)\b', re.IGNORECASE),
                re.compile(r'\b(?:username|user|email|login)\b.*\b(?:password|pass)\b', re.IGNORECASE),
            ]

            for pattern in login_patterns:
                if pattern.search(payload_content):
                    print("Login-related pattern detected in packet:", packet)
                    return 1

            # Check for HTTP response code indicating successful login
            if '200' in packet.http.response_code:
                print("Successful login detected in packet:", packet)
                return 1

    except AttributeError as e:
        print(f"Error analyzing packet: {e}")

    return 0
def get_payload_content(packet):
    if hasattr(packet, 'payload') and hasattr(packet.payload, 'fields') and 'load' in packet.payload.fields:
        return packet.payload.load

    return None

def extract_failed_logins(packet):
    failed_login_patterns = [
        re.compile(r'\b(?:failed login|authentication failure)\b', re.IGNORECASE),
        re.compile(r'\b(?:login attempt failed|invalid user)\b', re.IGNORECASE),
        re.compile(r'\b(?:authentication error|unsuccessful login)\b', re.IGNORECASE),
        re.compile(r'\b(?:access denied|login incorrect)\b', re.IGNORECASE),
        re.compile(r'\b(?:authentication rejected|invalid credentials)\b', re.IGNORECASE),
        re.compile(r'\b(?:login failed for user|incorrect password)\b', re.IGNORECASE),
    ]

    num_failed_logins = 0
    payload_content = get_payload_content(packet)
    
    for pattern in failed_login_patterns:
        if pattern.search(str(packet)):
            print(f"failed login Condition Detected in Packet:\n{packet}")
            num_failed_logins=num_failed_logins+1
            return 1  # Root shell detected

    return num_failed_logins


def extract_source_bytes(packet):
    if hasattr(packet, 'payload') and hasattr(packet.payload, 'fields') and 'load' in packet.payload.fields:
        return len(packet.payload.load)
    else:
        return 0

def extract_destination_bytes(packet):
    if hasattr(packet, 'payload') and hasattr(packet.payload, 'fields') and 'load' in packet.payload.fields:
        return len(packet.payload.load)
    else:
        return 0

def extract_flags(packet):
    if 'tcp' or 'TCP' in packet:
        return get_tcp_flags(packet.tcp.flags)
    elif 'icmp' in packet:
        return get_icmp_type(packet.icmp.type)
    elif 'udp' in packet:
        return 'SF'  
    else:
        return 'N/A'

def extract_destination_service(packet):
    if 'tcp' in packet or 'udp' in packet:
        port = packet[packet.transport_layer].dstport
        
        if packet and hasattr(packet, 'transport_layer') and ('tcp' in packet or 'udp' in packet):
                destination_port = packet[packet.transport_layer].dstport
                
                destination_service = get_service_name(destination_port)
                if destination_service==None:
                     destination_service="private"
                return (destination_service)


        
    else:
        return 'private'

def extract_wrong_fragment(packet):
    return int(getattr(packet, 'wrong_fragment', 0))

def get_service_name(port):
    try:
        service_name = socket.getservbyport(int(port))
        return service_name
    except (socket.error, OSError):
        return 'Unknown'

def resolve_mdns(port):
    dns_name = None

    def mdns_callback(pkt):
        nonlocal dns_name
        if pkt.haslayer(DNSRR) and pkt[DNSRR].type == 12:  # DNS type 12 is PTR (Pointer) record
            dns_name = pkt[DNSRR].rdata.decode('utf-8')

    sniff(prn=mdns_callback, timeout=2, filter=f"udp and port {port}")

    return dns_name

def get_tcp_flags(flags_hex):
    flag_names = {
        '0x0010': 'S3',
        '0x0002': 'S2',
        '0x0004': 'REJ',
        '0x0011': 'S3',
        '0x0020': 'URG',
        '0x0040': 'PSH',
        '0x0000': 'S0',
        '0x0001': 'S1',
        '0x0028': 'S2',
        '0x0018': 'S1',
        '0x0000': 'SF'
    }
    # Convert hex flag values to flag names
    return ', '.join(flag_names.get(flag, flag) for flag in flags_hex.split(',')) if flags_hex != 'N/A' else 'N/A'

def get_icmp_type(type_hex):
    # Map hex type values to type names
    type_names = {
        '0x08': 'Echo Request',
        '0x00': 'Echo Reply',
        # Add more types as needed
    }

    # Convert hex type values to type names
    return type_names.get(type_hex, type_hex)


# Start capturing packets in real-time (you might need administrative privileges)
def capture_and_process(interface='en0'):
    # Create a LiveCapture object to continuously capture packets
    
    capture = pyshark.LiveCapture(interface=interface)
    columns = ["duration", "protocol", "service", "flag", "src_bytes", "dst_bytes", "land",
           "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
           "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
           "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
           "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
           "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
           "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
           "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
           "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
           "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack", "last_flag"]

    dataset_path = 'test.csv'
    df = pd.read_csv(dataset_path, names=columns)


    df['target'] = (df['attack'] != 'normal').astype(int)

    df.drop(['attack', 'last_flag'], axis=1, inplace=True)

    X_train, X_test, y_train, y_test = \
        train_test_split(df.drop('target', axis=1), df['target'], test_size=0.2, random_state=42)

# Standardize numeric features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train.select_dtypes(include=['float64', 'int64']))
    X_test_scaled = scaler.transform(X_test.select_dtypes(include=['float64', 'int64']))

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)


# Model evaluation
#     print("Classification Report:\n", classification_report(y_test, predictions, zero_division=1))
#     print("Confusion Matrix:\n", confusion_matrix(y_test, predictions))
#     print("Accuracy:", accuracy_score(y_test, predictions))

# # Confusion matrix visualization
#     cm = confusion_matrix(y_test, predictions)
#     plt.figure(figsize=(8, 6))
#     sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
#     plt.title("Confusion Matrix")
#     plt.xlabel("Predicted")
#     plt.ylabel("True")
#     plt.show()

# # Print instances with incorrect predictions

# # Print accuracy percentage
#     accuracy = accuracy_score(y_test, predictions)
#     accuracy_percentage = accuracy * 100
#     print("Accuracy Percentage: {:.2f}%".format(accuracy_percentage))

    #Loop indefinitely to continuously capture and process packets
    for packet in capture.sniff_continuously():
        
        encrypted_keys=["Layer TLS","Layer SSL","Layer HTTPS"]
        for keys in encrypted_keys:
            if keys in packet:
                print("Encrypted Packet :")
                #print(packet)
                continue
            
        
        
        data = process_packet(packet)
        
        
        if data!=None: 
            

            sample_df = pd.DataFrame([data], index=['sample'])

            sample_df_encoded = pd.get_dummies(sample_df, columns=["protocol", "service", "flag"])

            sample_scaled = scaler.transform(sample_df_encoded.select_dtypes(include=['float64', 'int64']))

            sample_predictions = model.predict(sample_scaled)

            for prediction in sample_predictions:

                if prediction == 1:  # If prediction is an attack
                    print("Packet possible malacious:")
                    print("Packet Information:")
                    print(packet)
                    decision = input("Block IP address and stop capturing packets? (yes/no): ").lower()
                    if decision == 'yes':
                        ip_address = data['src_ip']  # Get the source IP address from the packet
                        block_ip(ip_address)  # Block the source IP address
                        break  # Stop capturing packets
                    elif decision == 'no':
                        continue  # Continue capturing packets
                else:
                    print("Normal")

        
def block_ip(ip_address):
    try:
        subprocess.run(['sudo', 'pfctl', '-e', 'block', 'in', 'from', ip_address], check=True)
        print(f"Blocked IP address {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP address {ip_address}: {e}")
capture_and_process()
print("Data")