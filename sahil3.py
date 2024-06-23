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
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pyshark
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report
import warnings
import subprocess
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext, messagebox
import sys

previous_timestamp = None  
connection_data = {}  
urgent_packets_count = 0  
processed_data={}
prev_src_ip = None
prev_dest_ip = None
prev_src_port = None
prev_dest_port = None
def process_packet(packet):
    global previous_timestamp, connection_data, urgent_packets_count
    global processed_data
    try:
        
        if hasattr(packet, 'ip') and hasattr(packet, 'transport_layer') and hasattr(packet, 'length'):
            if 'IP' in packet:

            
                protocol = 'unknown'
            
                if 'TCP' in packet:
                    src_port = int(packet.tcp.srcport)
                    dest_port = int(packet.tcp.dstport)
                    protocol = 'tcp'
                
                elif 'UDP' in packet:
                    src_port = int(packet.udp.srcport)
                    dest_port = int(packet.udp.dstport)
                    protocol = 'udp'
            timestamp = float(packet.sniff_timestamp)
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            
            length = int(packet.length)
            Land=calculate_land(packet)
            count=count_recent_connections(packet)
            Root_shell = detect_root_shell14(packet)
            detect_logins_guest=detect_guest_login(packet)
            
            destination_service = get_service_from_nmap(packet)
            Num_Ftp_Commands=calculate_outbound_ftp_commands(packet)
            srv_count=count_recent_connections_service(packet)
            flags = monitor_connection(packet)
            srv_serror_rate=count_recent_service_connection(packet,srv_count)
            #srv_serror_rate=count_recent_service_connection(packet)
            file_access=detect_file_access(packet)
            
            
            source_bytes = calculate_payload_length(packet)
            destination_bytes = calculate_dst_to_src_bytes(packet)
            shell_prompts=detect_shell_prompt(packet)
            Num_file_creation=detect_file_creation(packet)
            is_hot_login_value=detect_hot_login(packet)
            serror_rate=count_recent_flag_connections(packet,count)
            #serror_rate=count_recent_flag_connections(packet)
            
            rerror_rate=count_recent_REJflag_connections(packet,count)
            #rerror_rate=count_recent_REJflag_connections(packet)

            #srv_rerror_rate=count_recent_REJflag_service_connections(packet)
            srv_rerror_rate=count_recent_REJflag_service_connections(packet,srv_count)

            same_srv_rate=calculate_samesrv_rate(packet)
            diff_srv_rate=calculate_Diff_srv_rate_rate(packet)
            srv_diff_host_rate=calculate_Srv_diff_host_rate(packet)
            
            dst_host_count=calculate_destination_host_sameIP(packet,destination_service,flags)
            #dst_host_count=calculate_destination_host_sameIP(packet)
           
            dst_host_srv_count=calculate_destination_host_samePort(packet,flags)
            #dst_host_srv_count=calculate_destination_host_samePort(packet)

            dst_host_same_srv_rate=calculate_Dst_host_same_srv_rate(packet,dst_host_count)
            #dst_host_same_srv_rate=calculate_Dst_host_same_srv_rate(packet)
            
            #dst_host_diffsrv_rate=calculate_Dst_host_diff_srv_rate(packet)
            dst_host_diffsrv_rate=calculate_Dst_host_diff_srv_rate(packet,dst_host_count)

            dst_host_samesrc_port_rate=calculate_Dst_host_same_src_port_rate(packet,dst_host_srv_count)
            #dst_host_samesrc_port_rate=calculate_Dst_host_same_src_port_rate(packet)

            dst_host_srv_diff_host_rate=calculate_Dst_host_srv_diff_host_rate(packet,dst_host_srv_count)
            #dst_host_srv_diff_host_rate=calculate_Dst_host_srv_diff_host_rate(packet)

            dst_host_serror_rate=calculate_Dst_host_serro_r_rate(packet,dst_host_count)
            #dst_host_serror_rate=calculate_Dst_host_serro_r_rate(packet)

            dst_host_srv_serror_rate=calculate_Dst_host_srv_s_error_rate(packet,dst_host_srv_count)
            #dst_host_srv_serror_rate=calculate_Dst_host_srv_s_error_rate(packet)

            dst_host_rerror_rate=calculate_Dst_host_rerro_r_rate(packet,dst_host_count)
            #dst_host_rerror_rate=calculate_Dst_host_rerro_r_rate(packet)

            dst_host_srv_rerror_rate=calculate_Dst_host_srv_r_error_rate(packet,dst_host_srv_count)
            #dst_host_srv_rerror_rate=calculate_Dst_host_srv_r_error_rate(packet)

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
            login_status = analyze_packet(packet)
            Num_compromise = Num_compromised(packet)
            # Calculate duration based on timestamp difference
            duration = timestamp - previous_timestamp if previous_timestamp is not None else 0
            previous_timestamp = timestamp

            # Update or initialize connection data
            connection_key = f"{source_ip}:{destination_ip}:{protocol}"
            if connection_key in connection_data:
                #connection_data[connection_key]['source_bytes'] += source_bytes
                #connection_data[connection_key]['destination_bytes'] += destination_bytes
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

            processed_data ={ 'duration': duration,
 'protocol': protocol,
 'service': destination_service,
 'flag': flags,
 'src_bytes': source_bytes,
 'dst_bytes': destination_bytes,
 'land': Land,
 'wrong_fragment': Wrong_fragment,
 'urgent': urgent_packets_count,
 'hot': Hot,
 'num_failed_logins': Num_failed_logins,
 'logged_in': login_status,
 'num_compromised': Num_compromise,
 'root_shell': Root_shell,
'su_attempted': Su_attempted,
 'num_root': Num_root,
 'num_file_creations': Num_file_creation,
 'num_shells': shell_prompts,
 'num_access_files': file_access,
 'num_outbound_cmds': Num_Ftp_Commands,
 'is_host_login': is_hot_login_value,
 'is_guest_login': detect_logins_guest,
 'count': count,
 'srv_count': srv_count,
 'serror_rate': serror_rate,
 'srv_serror_rate': srv_serror_rate,
 'rerror_rate': rerror_rate,
 'srv_rerror_rate': srv_rerror_rate,
 'same_srv_rate': same_srv_rate,
 'diff_srv_rate': diff_srv_rate,
 'srv_diff_host_rate': srv_diff_host_rate,
 'dst_host_count': dst_host_count,
 'dst_host_srv_count': dst_host_srv_count,
 'dst_host_same_srv_rate': dst_host_same_srv_rate,
 'dst_host_diff_srv_rate': dst_host_diffsrv_rate,
 'dst_host_same_src_port_rate': dst_host_samesrc_port_rate,
 'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate,
 'dst_host_serror_rate': dst_host_serror_rate,
 'dst_host_srv_serror_rate': dst_host_srv_serror_rate,
 'dst_host_rerror_rate': dst_host_rerror_rate,
 'dst_host_srv_rerror_rate': dst_host_srv_rerror_rate,   
            
            }
            return processed_data

        
    except AttributeError as e:
        # Ignore packets without the necessary attributes
        return None
    

# New Functions here ..................
def get_service_from_nmap(packet):
    if 'IP' in packet:
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            protocol = 'unknown'
            service = 'unknown'
            src_port = None
            dest_port = None
            
            if 'TCP' in packet:
                src_port = int(packet.tcp.srcport)
                dest_port = int(packet.tcp.dstport)
                protocol = 'TCP'
                
            elif 'UDP' in packet:
                src_port = int(packet.udp.srcport)
                dest_port = int(packet.udp.dstport)
                protocol = 'UDP'
    
    try:
        command = ["sudo", "nmap", "-sV", "-p", str(dest_port), "localhost"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stderr:
            return "Error executing nmap command:\n" + stderr.decode()
        else:
            lines = stdout.decode().splitlines()
            for line in lines:
                if "/tcp" in line or "/udp" in line:
                    service = line.split()[2]
                    return service
        return None
    except Exception as e:
        return "An error occurred: " + str(e)

def calculate_packet_duration(prev_packet_time, current_packet_time):
    if prev_packet_time is None:
        return None
    else:
        return (current_packet_time - prev_packet_time).total_seconds()

def monitor_connection(packet):
    if 'IP' in packet:
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            protocol = 'unknown'
            service = 'unknown'
            src_port = None
            dest_port = None
            
            if 'TCP' in packet:
                src_port = int(packet.tcp.srcport)
                dest_port = int(packet.tcp.dstport)
                protocol = 'TCP'
                
            elif 'UDP' in packet:
                src_port = int(packet.udp.srcport)
                dest_port = int(packet.udp.dstport)
                protocol = 'UDP'
    
    try:
        nmap_command = ["nmap", "-p", str(dest_port), "--unprivileged", dest_ip]
        nmap_output = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, universal_newlines=True)

        if "open" in nmap_output:
            return "SF"
        elif "closed" in nmap_output:
            return "S0"
        else:
            return "REJ"
    except subprocess.CalledProcessError as e:
        return f"An error occurred: {e}"

TTL_SECONDS = 2

#26




def calculate_payload_length(packet):
    if 'IP' in packet:
        ip_header_length = int(packet.ip.hdr_len) * 4
        if 'TCP' in packet:
            tcp_header_length = int(packet.tcp.hdr_len) * 4
            total_length = int(packet.ip.len)
            payload_length = total_length - ip_header_length - tcp_header_length
            return max(payload_length, 0)
        elif 'UDP' in packet:
            udp_header_length = 8
            total_length = int(packet.ip.len)
            payload_length = total_length - ip_header_length - udp_header_length
            return max(payload_length, 0)
    return 0

# Global variable to store recent connections
recent_connections = deque()

# Your existing functions...
#23
TTL_SECONDS = 2
from collections import deque
from datetime import datetime, timedelta

recent_connections = deque()
TTL_SECONDS = 2  # TTL is 2 seconds

def count_recent_connections(current_packet):
    if 'IP' in current_packet:
        
        dest_port = None
        
        if 'TCP' in current_packet:
            src_port = int(current_packet.tcp.srcport)
            dest_port = int(current_packet.tcp.dstport)
            
        elif 'UDP' in current_packet:
            src_port = int(current_packet.udp.srcport)
            dest_port = int(current_packet.udp.dstport)
            
    
    global recent_connections

    current_time = datetime.now()
    current_dest_ip = current_packet.ip.dst
    
    # Add the current packet's destination IP and timestamp to the deque
    recent_connections.append((current_dest_ip, current_time, dest_port))
    
    # Remove connections that are older than TTL_SECONDS
    cutoff_time = current_time - timedelta(seconds=TTL_SECONDS)
    while recent_connections and recent_connections[0][1] < cutoff_time:
        recent_connections.popleft()
    
    # Count the number of connections to the same destination host
    count = sum(1 for conn in recent_connections if conn[0] == current_dest_ip)

    return count

recent_service_connections = deque()
#24
# def count_recent_connections_service(packet):
#     if 'TCP' in packet:
#                 src_port = int(packet.tcp.srcport)
#                 dest_port = int(packet.tcp.dstport)
#                 protocol = 'TCP'
#                 service = get_service_from_nmap(packet)
#     elif 'UDP' in packet:
#                 src_port = int(packet.udp.srcport)
#                 dest_port = int(packet.udp.dstport)
#                 protocol = 'UDP'
#                 service = get_service_from_nmap(packet)
  
#     global recent_service_connections

#     current_time = datetime.now()
#     current_time_only = current_time.time()
#     current_dest_ip = packet.ip.dst
#     seconds_since_midnight = current_time_only.hour * 3600 + current_time_only.minute * 60 + current_time_only.second
#     current_service = service

#     # Add the current packet's service and timestamp to the list
#     if [dest_port, seconds_since_midnight] not in recent_service_connections:
#         recent_service_connections.append([dest_port, seconds_since_midnight,current_dest_ip])
#     #print(recent_service_connections)
#     # Remove connections that are older than TTL_SECONDS
#     recent_service_connections = [conn for conn in recent_service_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]


#     # Count the number of connections with the same service
#     count = sum(1 for desPort, _,_ in recent_service_connections if desPort == dest_port)

#     return count



def count_recent_connections_service(packet):
    dest_port=0
    if 'TCP' in packet:
        src_port = int(packet.tcp.srcport)
        dest_port = int(packet.tcp.dstport)
       
    elif 'UDP' in packet:
        src_port = int(packet.udp.srcport)
        dest_port = int(packet.udp.dstport)
        
    global recent_service_connections

    current_time = datetime.now()
    current_dest_ip = packet.ip.dst
    if dest_port==None:
         return 0
         
    # Add the current packet's service and timestamp to the deque
    recent_service_connections.append((dest_port, current_time, current_dest_ip))

    # Remove connections that are older than TTL_SECONDS
    cutoff_time = current_time - timedelta(seconds=TTL_SECONDS)
    while recent_service_connections and recent_service_connections[0][1] < cutoff_time:
        recent_service_connections.popleft()

    # Count the number of connections with the same destination port
    count = sum(1 for desPort, _, _ in recent_service_connections if desPort == dest_port)

    return count

#25
def count_recent_flag_connections(packet,count1):
    #if 'IP' in packet:
            
                    
    global recent_connections
    
    
    
    

    current_dest_ip = packet.ip.dst

    # Add the current packet's destination IP and timestamp to the list
    
    
    # Remove connections that are older than 2 seconds
    #recent_connections = [conn for conn in recent_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]
    
    
    # Count the number of connections to the same destination host
    count=0
    for i in range(len(recent_connections)):
         
         if (str(recent_connections[i][0]) == str(current_dest_ip) and monitor_connection(packet) in {'S0'}):
              
              count=count+1
    
    totalCount=count1
    if totalCount==0:
          return 0
    #print(count)
    percentage=count/totalCount
    return percentage

#26
def count_recent_service_connection(packet,srv_count):
    if 'IP' in packet:
            
            dest_port = None
            if 'TCP' in packet:
                    
                    dest_port = int(packet.tcp.dstport)
                    
            elif 'UDP' in packet:
                    src_port = int(packet.udp.srcport)
                    dest_port = int(packet.udp.dstport)
                    
   
    global recent_service_connections
    current_time = datetime.now()
    
    

    # Add the current packet's destination IP and timestamp to the list
    
    
    # Remove connections that are older than 2 seconds
    #recent_service_connections = [conn for conn in recent_service_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]
    
    
    
    # Count the number of connections to the same destination host
    count=0
    for i in range(len(recent_service_connections)):
         
         if (str(recent_service_connections[i][0]) == str(dest_port) and monitor_connection(packet) in {'S0','SF'}):
              
              count=count+1
    totalCount=srv_count
    
    percentage=count/totalCount
    
    return percentage
#27
def count_recent_REJflag_connections(packet,count2):
    if 'IP' in packet:
            
    
        global recent_connections
        totalCount=count2
        current_time = datetime.now()
        

        current_dest_ip = packet.ip.dst

        # Add the current packet's destination IP and timestamp to the list
        

        # Remove connections that are older than 2 seconds
        #recent_connections = [conn for conn in recent_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]

        # Count the number of connections to the same destination host
        
        count=0
        for i in range(len(recent_connections)):
            
            if (str(recent_connections[i][0]) == str(current_dest_ip) and monitor_connection(packet) in {'REJ'}):
                
                count=count+1
        

        #count = sum(1 for dest_ip, _ in recent_connections if (dest_ip == current_dest_ip and monitor_connection(packet.ip.dst,dest_port) in {'REJ'}) )
        
        percentage=count/totalCount
        
        return percentage
#28
def count_recent_REJflag_service_connections(packet,count3):
    if 'IP' in packet:
            
        dest_port = None
        if 'TCP' in packet:
                    
                    dest_port = int(packet.tcp.dstport)
                    
        elif 'UDP' in packet:
                    
                    dest_port = int(packet.udp.dstport)
                    
   
        global recent_service_connections
        
        
        # Add the current packet's destination IP and timestamp to the list
        

        # Remove connections that are older than 2 seconds
        #recent_service_connections = [conn for conn in recent_service_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]

        # Count the number of connections to the same destination host
        
        count=0
        for i in range(len(recent_service_connections)):
            
            if (str(recent_service_connections[i][0]) == str(dest_port) and monitor_connection(packet) in {'REJ'}):
                
                count=count+1
        

        #count = sum(1 for dest_ip, _ in recent_connections if (dest_ip == current_dest_ip and monitor_connection(packet.ip.dst,dest_port) in {'REJ'}) )
        
        
    
        totalCount=count3
        
        percentage=count/totalCount
        
        return percentage
#29
def calculate_samesrv_rate(packet):
     if 'IP' in packet:
            
            dest_ip = packet.ip.dst
            
            service = 'unknown'
            
            dest_port = None
            if 'TCP' in packet:
                    
                    dest_port = int(packet.tcp.dstport)
                    
                    
            elif 'UDP' in packet:
                    
                    dest_port = int(packet.udp.dstport)
                    
   
     global recent_connections
     currDestIp=dest_ip
     
     totalCount=1
     serviceCount=0
     newrs=[]
     
     for i in recent_connections:
          if i[0]==currDestIp:
               newrs.append(i)
               totalCount=totalCount+1
     #print("this is newrs",newrs)
     for i in newrs:
          if i[2]==dest_port:
               serviceCount=serviceCount+1
     
     return serviceCount/len(newrs)
#30
def calculate_Diff_srv_rate_rate(packet):
     if 'IP' in packet:
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            
            dest_port = None
            if 'TCP' in packet:
                    
                    dest_port = int(packet.tcp.dstport)
                    
            elif 'UDP' in packet:
                    
                    dest_port = int(packet.udp.dstport)
                    
                    
   
     global recent_connections
     currDestIp=dest_ip
     
     totalCount=1
     serviceCount=0
     newrs=[]
     
     for i in recent_connections:
          if i[0]==currDestIp:
               newrs.append(i)
               totalCount=totalCount+1
     #print("this is newrs",newrs)
     for i in newrs:
          if i[2]!=dest_port:
               serviceCount=serviceCount+1
     
     return serviceCount/len(newrs)

#31
def calculate_Srv_diff_host_rate(packet):
     if 'IP' in packet:
            
            dest_ip = packet.ip.dst
            
            dest_port = None
            if 'TCP' in packet:
                    
                    dest_port = int(packet.tcp.dstport)
                   
            elif 'UDP' in packet:
                    
                    dest_port = int(packet.udp.dstport)
                    
   
     global recent_service_connections
     
    
     totalCount=1
     serviceCount=0
     newrs=[]
     
     for i in recent_connections:
          if i[0]==dest_port:
               newrs.append(i)
               totalCount=totalCount+1
     #print("this is newrs",newrs)
     for i in newrs:
          if i[2]!=dest_ip:
               serviceCount=serviceCount+1
    #  print(serviceCount)
     
    #  print(serviceCount/len(newrs))
     if len(newrs)==0:
          return 0
     return serviceCount/len(newrs)

#32
destinationHotAddress={}
def calculate_destination_host_sameIP(packet,service,flag):
     if 'IP' in packet:
            
            
            
        global destinationHotAddress 
        currDestAddress=packet.ip.dst
        if currDestAddress in destinationHotAddress:
            destinationHotAddress[currDestAddress]=[destinationHotAddress[currDestAddress][0]+1,service,flag]
        else:
            destinationHotAddress[currDestAddress]=[1,service,flag]
        
        return destinationHotAddress[currDestAddress][0]

#33
destinationserviceAddress={}
def calculate_destination_host_samePort(packet,flag):
     if 'IP' in packet:
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            
            src_port = None
            dest_port = None
            if 'TCP' in packet:
                    src_port = int(packet.tcp.srcport)
                    dest_port = int(packet.tcp.dstport)
                    
                    flag=monitor_connection(packet)
            elif 'UDP' in packet:
                    src_port = int(packet.udp.srcport)
                    dest_port = int(packet.udp.dstport)
                    
                    flag=monitor_connection(packet)
     global destinationserviceAddress 
     
     if dest_port in destinationserviceAddress:
          destinationserviceAddress[dest_port]=[destinationserviceAddress[dest_port][0]+1,src_port,dest_ip,flag]
     
     else:
          destinationserviceAddress[dest_port]=[1,src_port,dest_ip,flag]
     
     return destinationserviceAddress[dest_port][0]

#34
def calculate_Dst_host_same_srv_rate(packet,Dst_host_count):
           if 'IP' in packet:
                src_ip = packet.ip.src
                dest_ip = packet.ip.dst
                
                
                global destinationHotAddress
                currIp=dest_ip
                if currIp in destinationHotAddress:
                    checkservice=destinationHotAddress[currIp][1]
                else:
                    return 1
                count=0
                tc=Dst_host_count
                for i in destinationHotAddress:
                    if i==currIp and destinationHotAddress[i][1]==checkservice:
                            count+=1
                return count/tc
#35          
def calculate_Dst_host_diff_srv_rate(packet,Dst_host_count):
           if 'IP' in packet:
            
                dest_ip = packet.ip.dst
                
                
                global destinationHotAddress
                currIp=dest_ip
                if currIp in destinationHotAddress:
                    checkservice=destinationHotAddress[currIp][1]
                else:
                    return 0
                count=0
                tc=Dst_host_count
                for i in destinationHotAddress:
                    if i== currIp and destinationHotAddress[i][1]!=checkservice:
                            count+=1
                return count/tc
    #36
def calculate_Dst_host_same_src_port_rate(packet,Dst_host_srv_count):
      if 'IP' in packet:
            
            dest_port = None
            if 'TCP' in packet:
                    
                    dest_port = int(packet.tcp.dstport)
                    
            elif 'UDP' in packet:
                    
                    dest_port = int(packet.udp.dstport)
                    
            global destinationserviceAddress
            
            if dest_port in destinationserviceAddress:
                  sourceport=destinationserviceAddress[dest_port][1]
            else:
                  return 0
            count=0
            tc=Dst_host_srv_count
            for i in destinationserviceAddress:
                  if i== dest_port and destinationserviceAddress[i][1]==sourceport:
                        count+=1
            return round(count/tc,2)
      
#37
def calculate_Dst_host_srv_diff_host_rate(packet,Dst_host_srv_count):
      if 'IP' in packet:
            
            dest_port = None
            if 'TCP' in packet:
                    
                    dest_port = int(packet.tcp.dstport)
                    
            elif 'UDP' in packet:
                    src_port = int(packet.udp.srcport)
                    dest_port = int(packet.udp.dstport)
                    
            global destinationserviceAddress
            
            if dest_port in destinationserviceAddress:
                  destinatioip=destinationserviceAddress[dest_port][2]
            else:
                  return 0
            count=0
            tc=Dst_host_srv_count
            for i in destinationserviceAddress:
                  if i== dest_port and destinationserviceAddress[i][2]!=destinatioip:
                        count+=1
            return round(count/tc,2)
#38   
def calculate_Dst_host_serro_r_rate(packet,Dst_host_count):
      if 'IP' in packet:
            
            dest_ip = packet.ip.dst
            
            
            global destinationHotAddress
            currIp=dest_ip
            
            
            count=0
            tc=Dst_host_count
            for i in destinationHotAddress:
                  if i==currIp and destinationHotAddress[i][2]=='S0':
                        count+=1
            return count/tc
             

#39
def calculate_Dst_host_srv_s_error_rate(packet,Dst_host_srv_count):
            if 'IP' in packet:
                src_ip = packet.ip.src
                dest_ip = packet.ip.dst
                
                dest_port = None
                if 'TCP' in packet:
                    src_port = int(packet.tcp.srcport)
                    dest_port = int(packet.tcp.dstport)
                    
                elif 'UDP' in packet:
                    
                    dest_port = int(packet.udp.dstport)
                    
            global destinationserviceAddress
            currIp=dest_ip
            
            
            count=0
            tc=Dst_host_srv_count
            for i in destinationserviceAddress:
                  if i==dest_port and destinationserviceAddress[i][3]=='S0':
                        count+=1
            return count/tc
      
#40
def calculate_Dst_host_rerro_r_rate(packet,Dst_host_count):
      if 'IP' in packet:
            
            dest_ip = packet.ip.dst
            
            
                   
            currIp=dest_ip
            
            
            count=0
            tc=Dst_host_count
            for i in destinationHotAddress:
                  if i==currIp and destinationHotAddress[i][2]=='REJ':
                        count+=1
            return count/tc
             
#41
def calculate_Dst_host_srv_r_error_rate(packet,Dst_host_srv_count):
      if 'IP' in packet:
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            
            
                    
            global destinationserviceAddress
            currIp=dest_ip
            
            
            count=0
            tc=Dst_host_srv_count
            for i in destinationserviceAddress:
                  if i==currIp and destinationserviceAddress[i][3]=='REJ':
                        count+=1
            return count/tc
             

     

def calculate_dst_to_src_bytes(packet):
    global prev_src_ip, prev_dest_ip, prev_src_port, prev_dest_port
    
    current_src_ip = packet.ip.src
    current_dest_ip = packet.ip.dst
    current_src_port = int(packet[packet.transport_layer].srcport)
    current_dest_port = int(packet[packet.transport_layer].dstport)
    
    dst_to_src_bytes = 0

    if (prev_src_ip == current_dest_ip and prev_dest_ip == current_src_ip and
        prev_src_port == current_dest_port and prev_dest_port == current_src_port):
       
        return packet.length
        # if 'IP' in packet:
        #     ip_header_length = int(packet.ip.hdr_len) * 4
        # if 'TCP' in packet:
        #     tcp_header_length = int(packet.tcp.hdr_len) * 4
        #     total_length = int(packet.ip.len)
        #     payload_length = total_length - ip_header_length - tcp_header_length
        #     return max(payload_length, 0)
        # elif 'UDP' in packet:
        #     udp_header_length = 8
        #     total_length = int(packet.ip.len)
        #     payload_length = total_length - ip_header_length - udp_header_length
        #     return max(payload_length, 0)

    prev_src_ip = current_src_ip
    prev_dest_ip = current_dest_ip
    prev_src_port = current_src_port
    prev_dest_port = current_dest_port

    return dst_to_src_bytes




def analyze_packet(packet):
    login_status = 0
    
    if 'TCP' in packet and hasattr(packet, 'tcp') and hasattr(packet, 'data'):
        payload = bytes(packet.data).decode('utf-8', errors='ignore')
        login_keywords = ["login", "username", "user", "signin", "password", "pass", "pwd", "authenticate"]
        success_keywords = ["200 OK", "welcome", "logged in", "success", "authenticated", "authorized"]
        
        if "HTTP" in packet:
            packet=packet.http
            if any(keyword in packet.lower() for keyword in login_keywords):
                login_status = 1
            elif any(keyword in payload for keyword in success_keywords):
                login_status = 1
        elif 'Xml' in packet:
            # Example handling for XmlLayer
            packet = packet.xml
            if any(keyword in packet.lower() for keyword in login_keywords):
                login_status = 1
            elif any(keyword in payload for keyword in success_keywords):
                login_status = 1
            # Access XML specific attributes
            
        elif packet.tcp.dstport == 443 or packet.tcp.srcport == 443:
            if any(keyword in payload.lower() for keyword in login_keywords):
                login_status = 1
            elif any(keyword in payload.lower() for keyword in success_keywords):
                login_status = 1
    
    return login_status











# def get_service_from_nmap(packet):
#     if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
            
#             if 'TCP' in packet:
#                 src_port = int(packet.tcp.srcport)
#                 dest_port = int(packet.tcp.dstport)
#                 protocol = 'TCP'
                
#             elif 'UDP' in packet:
#                 src_port = int(packet.udp.srcport)
#                 dest_port = int(packet.udp.dstport)
#                 protocol = 'UDP'
    
#     try:
#         command = ["sudo", "nmap", "-sV", "-p", str(dest_port), "localhost"]
#         process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         stdout, stderr = process.communicate()

#         if stderr:
#             return "Error executing nmap command:\n" + stderr.decode()
#         else:
#             lines = stdout.decode().splitlines()
#             for line in lines:
#                 if "/tcp" in line or "/udp" in line:
#                     service = line.split()[2]
#                     return service
#         return None
#     except Exception as e:
#         return "An error occurred: " + str(e)

# def calculate_packet_duration(prev_packet_time, current_packet_time):
#     if prev_packet_time is None:
#         return None
#     else:
#         return (current_packet_time - prev_packet_time).total_seconds()

# def monitor_connection(packet):
#     if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
            
#             if 'TCP' in packet:
#                 src_port = int(packet.tcp.srcport)
#                 dest_port = int(packet.tcp.dstport)
#                 protocol = 'TCP'
                
#             elif 'UDP' in packet:
#                 src_port = int(packet.udp.srcport)
#                 dest_port = int(packet.udp.dstport)
#                 protocol = 'UDP'
    
#     try:
#         nmap_command = ["nmap", "-p", str(dest_port), "--unprivileged", dest_ip]
#         nmap_output = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, universal_newlines=True)

#         if "open" in nmap_output:
#             return "SF"
#         elif "closed" in nmap_output:
#             return "S0"
#         else:
#             return "REJ"
#     except subprocess.CalledProcessError as e:
#         return f"An error occurred: {e}"

# TTL_SECONDS = 2






# def calculate_payload_length(packet):
#     if 'IP' in packet:
#         ip_header_length = int(packet.ip.hdr_len) * 4
#         if 'TCP' in packet:
#             tcp_header_length = int(packet.tcp.hdr_len) * 4
#             total_length = int(packet.ip.len)
#             payload_length = total_length - ip_header_length - tcp_header_length
#             return max(payload_length, 0)
#         elif 'UDP' in packet:
#             udp_header_length = 8
#             total_length = int(packet.ip.len)
#             payload_length = total_length - ip_header_length - udp_header_length
#             return max(payload_length, 0)
#     return 0

# # Global variable to store recent connections
# recent_connections = []

# # Your existing functions...
# #23
# TTL_SECONDS = 2
# def count_recent_connections(current_packet):
#     if 'IP' in current_packet:
#             src_ip = current_packet.ip.src
#             dest_ip = current_packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in current_packet:
#                     src_port = int(current_packet.tcp.srcport)
#                     dest_port = int(current_packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(current_packet)
#             elif 'UDP' in current_packet:
#                     src_port = int(current_packet.udp.srcport)
#                     dest_port = int(current_packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(current_packet)
   
   
#     global recent_connections

#     current_time = datetime.now()
    
#     current_time_only = current_time.time()
#     seconds_since_midnight = current_time_only.hour * 3600 + current_time_only.minute * 60 + current_time_only.second
    
    
#     current_dest_ip = current_packet.ip.dst
    
#     # Add the current packet's destination IP and timestamp to the list
#     if [current_dest_ip, seconds_since_midnight] not in recent_connections:
#         recent_connections.append([current_dest_ip, seconds_since_midnight,dest_port])
    
#     # Remove connections that are older than TTL_SECONDS
#     recent_connections = [conn for conn in recent_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]
#     #print(recent_connections)
#     # Count the number of connections to the same destination host
#     count = sum(1 for conn in recent_connections if conn[0] == current_dest_ip)

#     return count

# recent_service_connections = []
# #24
# def count_recent_connections_service(packet):
#     if 'TCP' in packet:
#                 src_port = int(packet.tcp.srcport)
#                 dest_port = int(packet.tcp.dstport)
#                 protocol = 'TCP'
#                 service = get_service_from_nmap(packet)
#     elif 'UDP' in packet:
#                 src_port = int(packet.udp.srcport)
#                 dest_port = int(packet.udp.dstport)
#                 protocol = 'UDP'
#                 service = get_service_from_nmap(packet)
  
#     global recent_service_connections

#     current_time = datetime.now()
#     current_time_only = current_time.time()
#     current_dest_ip = packet.ip.dst
#     seconds_since_midnight = current_time_only.hour * 3600 + current_time_only.minute * 60 + current_time_only.second
    

#     # Add the current packet's service and timestamp to the list
#     if [dest_port, seconds_since_midnight] not in recent_service_connections:
#         recent_service_connections.append([dest_port, seconds_since_midnight,current_dest_ip])
#     #print(recent_service_connections)
#     # Remove connections that are older than TTL_SECONDS
#     recent_service_connections = [conn for conn in recent_service_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]


#     # Count the number of connections with the same service
#     count = sum(1 for desPort, _,_ in recent_service_connections if desPort == dest_port)

#     return count


# #25
# def count_recent_flag_connections(packet):
#     if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
   
#     global recent_connections
    
#     current_time = datetime.now()
#     current_time_only = current_time.time()
#     seconds_since_midnight = current_time_only.hour * 3600 + current_time_only.minute * 60 + current_time_only.second

#     current_dest_ip = packet.ip.dst

#     # Add the current packet's destination IP and timestamp to the list
    
    
#     # Remove connections that are older than 2 seconds
#     #recent_connections = [conn for conn in recent_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]
    
    
#     # Count the number of connections to the same destination host
#     count=0
#     for i in range(len(recent_connections)):
         
#          if (str(recent_connections[i][0]) == str(current_dest_ip) and monitor_connection(packet) in {'S0'}):
              
#               count=count+1
    
#     totalCount=count_recent_connections(packet)
#     #print(count)
#     percentage=count/totalCount
#     return percentage

# #26
# def count_recent_service_connection(packet):
#     if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
   
#     global recent_service_connections
#     current_time = datetime.now()
#     current_time_only = current_time.time()
#     current_dest_ip = packet.ip.dst
#     seconds_since_midnight = current_time_only.hour * 3600 + current_time_only.minute * 60 + current_time_only.second

#     # Add the current packet's destination IP and timestamp to the list
    
    
#     # Remove connections that are older than 2 seconds
#     #recent_service_connections = [conn for conn in recent_service_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]
    
    
    
#     # Count the number of connections to the same destination host
#     count=0
#     for i in range(len(recent_service_connections)):
         
#          if (str(recent_service_connections[i][0]) == str(dest_port) and monitor_connection(packet) in {'S0','SF'}):
              
#               count=count+1
#     totalCount=count_recent_connections_service(packet)
    
#     percentage=count/totalCount
    
#     return percentage
# #27
# def count_recent_REJflag_connections(packet):
#     if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
   
#     global recent_connections
#     totalCount=count_recent_connections(packet)
#     current_time = datetime.now()
#     current_time_only = current_time.time()
#     seconds_since_midnight = current_time_only.hour * 3600 + current_time_only.minute * 60 + current_time_only.second


#     current_dest_ip = packet.ip.dst

#     # Add the current packet's destination IP and timestamp to the list
    

#     # Remove connections that are older than 2 seconds
#     #recent_connections = [conn for conn in recent_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]

#     # Count the number of connections to the same destination host
    
#     count=0
#     for i in range(len(recent_connections)):
         
#          if (str(recent_connections[i][0]) == str(current_dest_ip) and monitor_connection(packet) in {'REJ'}):
              
#               count=count+1
    

#     #count = sum(1 for dest_ip, _ in recent_connections if (dest_ip == current_dest_ip and monitor_connection(packet.ip.dst,dest_port) in {'REJ'}) )
    
#     percentage=count/totalCount
    
#     return percentage
# #28
# def count_recent_REJflag_service_connections(packet):
#     if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
   
#     global recent_service_connections
    
#     current_time = datetime.now()
#     current_time_only = current_time.time()
#     seconds_since_midnight = current_time_only.hour * 3600 + current_time_only.minute * 60 + current_time_only.second


#     current_dest_ip = packet.ip.dst

#     # Add the current packet's destination IP and timestamp to the list
    

#     # Remove connections that are older than 2 seconds
#     #recent_service_connections = [conn for conn in recent_service_connections if (seconds_since_midnight - conn[1]) <= TTL_SECONDS]

#     # Count the number of connections to the same destination host
    
#     count=0
#     for i in range(len(recent_service_connections)):
         
#          if (str(recent_service_connections[i][0]) == str(dest_port) and monitor_connection(packet) in {'REJ'}):
              
#               count=count+1
    

#     #count = sum(1 for dest_ip, _ in recent_connections if (dest_ip == current_dest_ip and monitor_connection(packet.ip.dst,dest_port) in {'REJ'}) )
    
    
   
#     totalCount=count_recent_connections_service(packet)
    
#     percentage=count/totalCount
    
#     return percentage
# #29
# def calculate_samesrv_rate(packet):
#      if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
   
#      global recent_connections
#      currDestIp=dest_ip
#      currService=service
#      totalCount=1
#      serviceCount=0
#      newrs=[]
     
#      for i in recent_connections:
#           if i[0]==currDestIp:
#                newrs.append(i)
#                totalCount=totalCount+1
#      #print("this is newrs",newrs)
#      for i in newrs:
#           if i[2]==dest_port:
#                serviceCount=serviceCount+1
     
#      return serviceCount/len(newrs)
# #30
# def calculate_Diff_srv_rate_rate(packet):
#      if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
   
#      global recent_connections
#      currDestIp=dest_ip
#      currService=service
#      totalCount=1
#      serviceCount=0
#      newrs=[]
     
#      for i in recent_connections:
#           if i[0]==currDestIp:
#                newrs.append(i)
#                totalCount=totalCount+1
#      #print("this is newrs",newrs)
#      for i in newrs:
#           if i[2]!=dest_port:
#                serviceCount=serviceCount+1
     
#      return serviceCount/len(newrs)

# #31
# def calculate_Srv_diff_host_rate(packet):
#      if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
   
#      global recent_service_connections
#      currDestIp=dest_ip
#      currService=service
#      totalCount=1
#      serviceCount=0
#      newrs=[]
     
#      for i in recent_connections:
#           if i[0]==dest_port:
#                newrs.append(i)
#                totalCount=totalCount+1
#      #print("this is newrs",newrs)
#      for i in newrs:
#           if i[2]!=dest_ip:
#                serviceCount=serviceCount+1
#     #  print(serviceCount)
     
#     #  print(serviceCount/len(newrs))
#      if len(newrs)==0:
#           return 0
#      return serviceCount/len(newrs)

# #32
# destinationHotAddress={}
# def calculate_destination_host_sameIP(packet):
#      if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
            
#      global destinationHotAddress 
#      currDestAddress=packet.ip.dst
#      if currDestAddress in destinationHotAddress:
#           destinationHotAddress[currDestAddress]=[destinationHotAddress[currDestAddress][0]+1,service,flag]
#      else:
#           destinationHotAddress[currDestAddress]=[1,service,flag]
     
#      return destinationHotAddress[currDestAddress][0]

# #33
# destinationserviceAddress={}
# def calculate_destination_host_samePort(packet):
#      if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#      global destinationserviceAddress 
     
#      if dest_port in destinationserviceAddress:
#           destinationserviceAddress[dest_port]=[destinationserviceAddress[dest_port][0]+1,src_port,dest_ip,flag]
     
#      else:
#           destinationserviceAddress[dest_port]=[1,src_port,dest_ip,flag]
     
#      return destinationserviceAddress[dest_port][0]

# #34
# def calculate_Dst_host_same_srv_rate(packet):
#            if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#             global destinationHotAddress
#             currIp=dest_ip
#             if currIp in destinationHotAddress:
#                   checkservice=destinationHotAddress[currIp][1]
#             else:
#                   return 1
#             count=0
#             tc=calculate_destination_host_sameIP(packet)
#             for i in destinationHotAddress:
#                   if i==currIp and destinationHotAddress[i][1]==checkservice:
#                         count+=1
#             return count/tc
# #35          
# def calculate_Dst_host_diff_srv_rate(packet):
#            if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#             global destinationHotAddress
#             currIp=dest_ip
#             if currIp in destinationHotAddress:
#                   checkservice=destinationHotAddress[currIp][1]
#             else:
#                   return 0
#             count=0
#             tc=calculate_destination_host_sameIP(packet)
#             for i in destinationHotAddress:
#                   if i== currIp and destinationHotAddress[i][1]!=checkservice:
#                         count+=1
#             return count/tc
# #36
# def calculate_Dst_host_same_src_port_rate(packet):
#       if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#             global destinationserviceAddress
            
#             if dest_port in destinationserviceAddress:
#                   sourceport=destinationserviceAddress[dest_port][1]
#             else:
#                   return 0
#             count=0
#             tc=calculate_destination_host_samePort(packet)
#             for i in destinationserviceAddress:
#                   if i== dest_port and destinationserviceAddress[i][1]==sourceport:
#                         count+=1
#             return round(count/tc,2)
      
# #37
# def calculate_Dst_host_srv_diff_host_rate(packet):
#       if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#             global destinationserviceAddress
            
#             if dest_port in destinationserviceAddress:
#                   destinatioip=destinationserviceAddress[dest_port][2]
#             else:
#                   return 0
#             count=0
#             tc=calculate_destination_host_samePort(packet)
#             for i in destinationserviceAddress:
#                   if i== dest_port and destinationserviceAddress[i][2]!=destinatioip:
#                         count+=1
#             return round(count/tc,2)
# #38   
# def calculate_Dst_host_serro_r_rate(packet):
#       if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             global destinationHotAddress
#             currIp=dest_ip
            
            
#             count=0
#             tc=calculate_destination_host_sameIP(packet)
#             for i in destinationHotAddress:
#                   if i==currIp and destinationHotAddress[i][2]=='S0':
#                         count+=1
#             return round(count/tc,2)
             

# #39
# def calculate_Dst_host_srv_s_error_rate(packet):
#             if 'IP' in packet:
#                 src_ip = packet.ip.src
#                 dest_ip = packet.ip.dst
#                 protocol = 'unknown'
#                 service = 'unknown'
#                 src_port = None
#                 dest_port = None
#                 if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#                 elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             global destinationserviceAddress
#             currIp=dest_ip
            
            
#             count=0
#             tc=calculate_destination_host_samePort(packet)
#             for i in destinationserviceAddress:
#                   if i==dest_port and destinationserviceAddress[i][3]=='S0':
#                         count+=1
#             return round(count/tc,2)
      
# #40
# def calculate_Dst_host_rerro_r_rate(packet):
#       if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             currIp=dest_ip
            
            
#             count=0
#             tc=calculate_destination_host_sameIP(packet)
#             for i in destinationHotAddress:
#                   if i==currIp and destinationHotAddress[i][2]=='REJ':
#                         count+=1
#             return round(count/tc,2)
             
# #41
# def calculate_Dst_host_srv_r_error_rate(packet):
#       if 'IP' in packet:
#             src_ip = packet.ip.src
#             dest_ip = packet.ip.dst
#             protocol = 'unknown'
#             service = 'unknown'
#             src_port = None
#             dest_port = None
#             if 'TCP' in packet:
#                     src_port = int(packet.tcp.srcport)
#                     dest_port = int(packet.tcp.dstport)
#                     protocol = 'TCP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             elif 'UDP' in packet:
#                     src_port = int(packet.udp.srcport)
#                     dest_port = int(packet.udp.dstport)
#                     protocol = 'UDP'
#                     service = get_service_from_nmap(packet)
#                     flag=monitor_connection(packet)
#             global destinationHotAddress
#             currIp=dest_ip
            
            
#             count=0
#             tc=calculate_destination_host_sameIP(packet)
#             for i in destinationHotAddress:
#                   if i==currIp and destinationHotAddress[i][2]=='REJ':
#                         count+=1
#             return round(count/tc,2)
             

     

# def calculate_dst_to_src_bytes(packet):
#     global prev_src_ip, prev_dest_ip, prev_src_port, prev_dest_port
    
#     current_src_ip = packet.ip.src
#     current_dest_ip = packet.ip.dst
#     current_src_port = int(packet[packet.transport_layer].srcport)
#     current_dest_port = int(packet[packet.transport_layer].dstport)
    
#     dst_to_src_bytes = 0

#     if (prev_src_ip == current_dest_ip and prev_dest_ip == current_src_ip and
#         prev_src_port == current_dest_port and prev_dest_port == current_src_port):
       
#         return packet.length
#         # if 'IP' in packet:
#         #     ip_header_length = int(packet.ip.hdr_len) * 4
#         # if 'TCP' in packet:
#         #     tcp_header_length = int(packet.tcp.hdr_len) * 4
#         #     total_length = int(packet.ip.len)
#         #     payload_length = total_length - ip_header_length - tcp_header_length
#         #     return max(payload_length, 0)
#         # elif 'UDP' in packet:
#         #     udp_header_length = 8
#         #     total_length = int(packet.ip.len)
#         #     payload_length = total_length - ip_header_length - udp_header_length
#         #     return max(payload_length, 0)

#     prev_src_ip = current_src_ip
#     prev_dest_ip = current_dest_ip
#     prev_src_port = current_src_port
#     prev_dest_port = current_dest_port

#     return dst_to_src_bytes




# def analyze_packet(packet):
#     login_status = 0
    
#     if 'TCP' in packet and hasattr(packet, 'tcp') and hasattr(packet, 'data'):
#         payload = bytes(packet.data).decode('utf-8', errors='ignore')
#         login_keywords = ["login", "username", "user", "signin", "password", "pass", "pwd", "authenticate"]
#         success_keywords = ["200 OK", "welcome", "logged in", "success", "authenticated", "authorized"]
        
#         if "HTTP" in payload:
#             if any(keyword in payload.lower() for keyword in login_keywords):
#                 login_status = 1
#             elif any(keyword in payload for keyword in success_keywords):
#                 login_status = 1
        
#         elif packet.tcp.dstport == 443 or packet.tcp.srcport == 443:
#             if any(keyword in payload.lower() for keyword in login_keywords):
#                 login_status = 1
#             elif any(keyword in payload.lower() for keyword in success_keywords):
#                 login_status = 1
    
#     return login_status



#######################################################################










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
            
            return 1  # Detected compromised condition

    return 0  


def extract_login_status(packet):
    login_status = 0
    
    if 'TCP' in packet and hasattr(packet, 'tcp') and hasattr(packet, 'data'):
        payload = bytes(packet.data).decode('utf-8', errors='ignore')
        login_keywords = ["login", "username", "user", "signin", "password", "pass", "pwd", "authenticate"]
        success_keywords = ["200 OK", "welcome", "logged in", "success", "authenticated", "authorized"]
        
        if "HTTP" in payload:
            if any(keyword in payload.lower() for keyword in login_keywords):
                login_status = 1
            elif any(keyword in payload for keyword in success_keywords):
                login_status = 1
        
        elif packet.tcp.dstport == 443 or packet.tcp.srcport == 443:
            if any(keyword in payload.lower() for keyword in login_keywords):
                login_status = 1
            elif any(keyword in payload.lower() for keyword in success_keywords):
                login_status = 1
    
    return login_status

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
            
            num_failed_logins=num_failed_logins+1
            return 1  # Root shell detected

    return num_failed_logins


def extract_source_bytes(packet):
    if 'IP' in packet:
        ip_header_length = int(packet.ip.hdr_len) * 4
        if 'TCP' in packet:
            tcp_header_length = int(packet.tcp.hdr_len) * 4
            total_length = int(packet.ip.len)
            payload_length = total_length - ip_header_length - tcp_header_length
            return max(payload_length, 0)
        elif 'UDP' in packet:
            udp_header_length = 8
            total_length = int(packet.ip.len)
            payload_length = total_length - ip_header_length - udp_header_length
            return max(payload_length, 0)
    return 0

def extract_destination_bytes(packet):
    global prev_src_ip, prev_dest_ip, prev_src_port, prev_dest_port
    
    current_src_ip = packet.ip.src
    current_dest_ip = packet.ip.dst
    current_src_port = int(packet[packet.transport_layer].srcport)
    current_dest_port = int(packet[packet.transport_layer].dstport)
    
    dst_to_src_bytes = 0

    if (prev_src_ip == current_dest_ip and prev_dest_ip == current_src_ip and
        prev_src_port == current_dest_port and prev_dest_port == current_src_port):
        
        return packet.length
        # if 'IP' in packet:
        #     ip_header_length = int(packet.ip.hdr_len) * 4
        # if 'TCP' in packet:
        #     tcp_header_length = int(packet.tcp.hdr_len) * 4
        #     total_length = int(packet.ip.len)
        #     payload_length = total_length - ip_header_length - tcp_header_length
        #     return max(payload_length, 0)
        # elif 'UDP' in packet:
        #     udp_header_length = 8
        #     total_length = int(packet.ip.len)
        #     payload_length = total_length - ip_header_length - udp_header_length
        #     return max(payload_length, 0)

    prev_src_ip = current_src_ip
    prev_dest_ip = current_dest_ip
    prev_src_port = current_src_port
    prev_dest_port = current_dest_port

    return dst_to_src_bytes



def extract_flags(packet):
   if 'IP' in packet:
            src_ip = packet.ip.src
            dest_ip = packet.ip.dst
            protocol = 'unknown'
            service = 'unknown'
            src_port = None
            dest_port = None
            
            if 'TCP' in packet:
                src_port = int(packet.tcp.srcport)
                dest_port = int(packet.tcp.dstport)
                protocol = 'TCP'
                
            elif 'UDP' in packet:
                src_port = int(packet.udp.srcport)
                dest_port = int(packet.udp.dstport)
                protocol = 'UDP'
    
   try:
        nmap_command = ["nmap", "-p", str(dest_port), "--unprivileged", dest_ip]
        nmap_output = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, universal_newlines=True)

        if "open" in nmap_output:
            return "SF"
        elif "closed" in nmap_output:
            return "S0"
        else:
            return "REJ"
   except subprocess.CalledProcessError as e:
        return f"An error occurred: {e}"


def get_service_from_nmap(packet):
    if 'TCP' in packet:
                src_port = int(packet.tcp.srcport)
                dest_port = int(packet.tcp.dstport)
                protocol = 'TCP'
                
    elif 'UDP' in packet:
                src_port = int(packet.udp.srcport)
                dest_port = int(packet.udp.dstport)
                protocol = 'UDP'
    try:
        command = ["sudo", "nmap", "-sV", "-p", str(dest_port), "localhost"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stderr:
            return "Error executing nmap command:\n" + stderr.decode()
        else:
            lines = stdout.decode().splitlines()
            for line in lines:
                if "/tcp" in line or "/udp" in line:
                    service = line.split()[2]
                    return service
        return None
    except Exception as e:
        return "An error occurred: " + str(e)

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


#Start capturing packets in real-time (you might need administrative privileges)
# def capture_and_process(interface='en0'):
#     # Create a LiveCapture object to continuously capture packets
#    def process_packet(packet):
#     # Placeholder for actual packet processing logic
#     # Return a dictionary with processed packet data
#     return {
#         'duration': 0, 'protocol_type': 'icmp', 'service': 'eco_i', 'flag': 'SF', 'src_bytes': 8, 'dst_bytes': 0,
#         'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
#         'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
#         'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
#         'count': 1, 'srv_count': 44, 'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
#         'same_srv_rate': 1, 'diff_srv_rate': 0, 'srv_diff_host_rate': 1, 'dst_host_count': 1, 'dst_host_srv_count': 95,
#         'dst_host_same_srv_rate': 1, 'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1, 'dst_host_srv_diff_host_rate': 0.51,
#         'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0,
#         'attack': 'normal', "last_flag": 21
#     }

# def block_ip(ip_address):
#     try:
#         subprocess.run(['sudo', 'pfctl', '-e', 'block', 'in', 'from', ip_address], check=True)
#         print(f"Blocked IP address {ip_address}")
#     except subprocess.CalledProcessError as e:
#         print(f"Error blocking IP address {ip_address}: {e}")
 # Initially, capture is active
capture_active = threading.Event()
def capture_and_process(interface='en0'):
    global capture_active
    # Load and preprocess the dataset
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

    dataset_path = 'train.csv'
    df = pd.read_csv(dataset_path, names=columns)

    # Preprocess the dataset
    df.drop(['land', 'urgent', 'num_failed_logins', 'num_outbound_cmds'], axis=1, inplace=True)
    df.fillna(0, inplace=True)

    le_protocol = LabelEncoder()
    df['protocol'] = le_protocol.fit_transform(df['protocol'])

    le_service = LabelEncoder()
    df['service'] = le_service.fit_transform(df['service'])

    le_flag = LabelEncoder()
    df['flag'] = le_flag.fit_transform(df['flag'])

    le_attack = LabelEncoder()
    df['attack'] = le_attack.fit_transform(df['attack'])

    X = df.drop(['attack', 'last_flag'], axis=1)
    y = df['attack']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = SVC(kernel='rbf', random_state=42)
    model.fit(X_scaled, y)

    capture = pyshark.LiveCapture(interface=interface)
    
    for packet in capture.sniff_continuously():
        if not capture_active.is_set():
                break
        
        encrypted_keys = ["Layer TLS", "Layer SSL", "Layer HTTPS"]
        if any(key in packet for key in encrypted_keys):
            print("Encrypted Packet:")
            continue

        data = process_packet(packet)
        if data is not None:
            
            sample_df = pd.DataFrame([data])
            sample_df['protocol'] = le_protocol.transform(sample_df['protocol'].apply(lambda x: x if x in le_protocol.classes_ else 'other'))
            sample_df['service'] = le_service.transform(sample_df['service'].apply(lambda x: x if x in le_service.classes_ else 'other'))
            sample_df['flag'] = le_flag.transform(sample_df['flag'].apply(lambda x: x if x in le_flag.classes_ else 'other'))

            sample_df.drop(['land', 'urgent', 'num_failed_logins', 'num_outbound_cmds'], axis=1, inplace=True)
            sample_df = sample_df[X.columns]

            new_sample_scaled = scaler.transform(sample_df)
            new_sample_pred = model.predict(new_sample_scaled)
            new_sample_pred_label = le_attack.inverse_transform(new_sample_pred)
             # Display the prediction for the packet
            text_widget.insert(tk.END, f"Prediction for the new incoming packet: {new_sample_pred_label[0]}\n")
            #text_widget.insert(tk.END, f"Packet Information: {packet}\n")
            text_widget.yview(tk.END)
            text_widget.update()  # Update the text widget to refresh display


            print("Prediction for the new incoming tcp/udp packet :", new_sample_pred_label[0])
            if new_sample_pred_label[0] !="normal":
                text_widget.insert(tk.END, f"Capture Packet Information Possible Malcious click to block IP address : \n {packet}")

                decision = messagebox.askyesno("Block IP", f"Block IP address and stop capturing packets?\n\n Check Packet in the display:")
                
                if decision:
                        ip_address = data.get('src_ip', 'Unknown')
                        block_ip(ip_address)
                        capture_active.clear()
                        break
                print("Packet possible malicious:")
                print("Packet Information:", packet)
                #display_packet_info("Packet possible malicious:\n")
                #display_packet_info(f"Packet Information: {packet}\n")
                #decision = input("Block IP address and stop capturing packets? (yes/no): ").lower()
                # if decision == 'yes':
                #     ip_address = data.get('src_ip', 'Unknown')
                #     block_ip(ip_address)
                #     break
        
def block_ip(ip_address):
    try:
        subprocess.run(['sudo', 'pfctl', '-e', 'block', 'in', 'from', ip_address], check=True)
        print(f"Blocked IP address {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP address {ip_address}: {e}")


def display_packet_info(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.yview(tk.END)

def start_capture():
    messagebox.showinfo("Please wait", "Please wait till the model gets trained")
    global capture_active
    if not capture_active.is_set():
        capture_active.set()
        threading.Thread(target=capture_and_process, args=("en0",)).start()
    else:
        m = messagebox.INFO("Cature Already Active")

        print("Capture already active.")

def stop_execution():
    global capture_active
    capture_active.clear()
    print("Capture stopped.")
    sys.exit(0)

def create_gui():
    global text_widget

    root = tk.Tk()
    root.title("Packet Analyzer")
    text_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
    text_widget.pack(padx=10, pady=10)

    stop_button = tk.Button(root, text="Stop Packet Capture", command=stop_execution)
    stop_button.pack(pady=10)

    start_button = tk.Button(root, text="Start Packet Capture", command=start_capture)
    start_button.pack(pady=10)

    root.mainloop()

# Start the GUI
create_gui()

















# # Define the process_packet function or remove its reference if not needed
# def process_packet(packet):
#     # Placeholder for actual packet processing logic
#     pass

# def capture_and_process(interface='en0'):
#     # Load and preprocess the dataset
#     columns = ["duration", "protocol", "service", "flag", "src_bytes", "dst_bytes", "land",
#                "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
#                "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
#                "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
#                "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
#                "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
#                "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
#                "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
#                "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
#                "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack", "last_flag"]

#     dataset_path = 'train.csv'  # Provide the correct path to your dataset file
#     df = pd.read_csv(dataset_path, names=columns)

#     # Preprocess the dataset
#     df.drop(['land', 'urgent', 'num_failed_logins', 'num_outbound_cmds'], axis=1, inplace=True)
#     df.fillna(0, inplace=True)

#     le_protocol = LabelEncoder()
#     df['protocol'] = le_protocol.fit_transform(df['protocol'])

#     le_service = LabelEncoder()
#     df['service'] = le_service.fit_transform(df['service'])

#     le_flag = LabelEncoder()
#     df['flag'] = le_flag.fit_transform(df['flag'])

#     le_attack = LabelEncoder()
#     df['attack'] = le_attack.fit_transform(df['attack'])

#     X = df.drop(['attack', 'last_flag'], axis=1)
#     y = df['attack']

#     scaler = StandardScaler()
#     X_scaled = scaler.fit_transform(X)

#     # RandomForest without hyperparameter tuning
#     rf = RandomForestClassifier(random_state=42)
#     rf.fit(X_scaled, y)

#     model = rf

#     capture = pyshark.LiveCapture(interface=interface)

#     # ThreadPoolExecutor for asynchronous processing
#     executor = ThreadPoolExecutor(max_workers=5)
#     futures = []

#     def process_and_predict(packet):
#         data = process_packet(packet)
#         if data is not None:
#             sample_df = pd.DataFrame([data])
#             sample_df['protocol'] = le_protocol.transform(sample_df['protocol'].apply(lambda x: x if x in le_protocol.classes_ else 'other'))
#             sample_df['service'] = le_service.transform(sample_df['service'].apply(lambda x: x if x in le_service.classes_ else 'other'))
#             sample_df['flag'] = le_flag.transform(sample_df['flag'].apply(lambda x: x if x in le_flag.classes_ else 'other'))

#             sample_df.drop(['land', 'urgent', 'num_failed_logins', 'num_outbound_cmds'], axis=1, inplace=True)
#             sample_df = sample_df[X.columns]

#             new_sample_scaled = scaler.transform(sample_df)
#             new_sample_pred = model.predict(new_sample_scaled)
#             new_sample_pred_label = le_attack.inverse_transform(new_sample_pred)

#             print("Prediction for the new incoming tcp/udp packet :", new_sample_pred_label[0])
#             if new_sample_pred_label == 1:
#                 print("Packet possible malicious:")
#                 print("Packet Information:", packet)
#                 decision = input("Block IP address and stop capturing packets? (yes/no): ").lower()
#                 if decision == 'yes':
#                     ip_address = data.get('src_ip', 'Unknown')
#                     block_ip(ip_address)
#                     return True
#         return False

#     for packet in capture.sniff_continuously():
#         if any(key in packet for key in ["Layer TLS", "Layer SSL", "Layer HTTPS"]):
#             print("Encrypted Packet:")
#             continue
#         futures.append(executor.submit(process_and_predict, packet))

#     # Handle the results of the futures
#     for future in as_completed(futures):
#         if future.result():
#             break

# def start_capture():
#     # Use threading to prevent blocking the main thread
#     threading.Thread(target=capture_and_process).start()

# def create_gui():
#     root = tk.Tk()
#     root.title("Packet Capture GUI")

#     frame = tk.Frame(root)
#     frame.pack(padx=10, pady=10)

#     start_button = tk.Button(frame, text="Start Packet Capture", command=start_capture)
#     start_button.pack(pady=10)

#     exit_button = tk.Button(frame, text="Exit", command=root.quit)
#     exit_button.pack(pady=10)

#     root.mainloop()

# if __name__ == "__main__":
#     create_gui()

