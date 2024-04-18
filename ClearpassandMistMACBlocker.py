from pyclearpass import *
import re
import requests
from flask import *
from flask_cors import *
import json


def processMAC(MAC_ADD): 
    try: 
        normalized_mac = re.sub(r'[^0-9a-f]', '', MAC_ADD.lower())  
        formatted_mac = ':'.join(normalized_mac[i:i+2] for i in range(0, 12, 2)) 
        return formatted_mac 
    except Exception as e: 
        return f"Error processing MAC address: {e}"

def Clearpass(MAC_ADD, des, server, token, ID):
    try:
        login = ClearPassAPILogin(server = server,granttype="client_credentials",
        clientsecret=token, clientid="NET_SERVICES_API_CLIENT", verify_ssl=True)
        static_host_list = ApiIdentities.get_static_host_list_name_by_name(login, name="Blocked_Device_MACs")
        static_host_list = static_host_list.pop("host_entries")
        static_host_list.append({"host_address": MAC_ADD, "host_address_desc" : des})
        ApiIdentities.update_static_host_list_by_static_host_list_id(login, static_host_list_id= ID, body=({
            "name" : "Blocked_Device_MACs", #Name of the static host list. Object Type: string
            "description" : "Blocked Vendor MACs", #Description of the static host list. Object Type: string
            "host_format" : "list", #Format of the static host list. Object Type: string
            "host_type" : "MACAddress", #Host type of the static host list. Object Type: string
            "host_entries": static_host_list, #List of host entries (Address and Description) for the host format "List". For example, "host_entries":[{"host_address": "10.21.11.117", "host_address_desc" : "My host address description."}, {..} ..]. Object Type: object
            }))

        static_host_list = ApiIdentities.get_static_host_list_name_by_name(login, name="Blocked_Device_MACs")
        print(f"\n\n\n\n\n\n{static_host_list}")
        e = f"It worked here is the new Blocked MAC address list{static_host_list}"
        print(static_host_list, "clearpass function")
        return static_host_list
    except Exception as e:
         e = f"Error in Clearpass function: {e}"



def mist(MAC_ADD, MISTURL, MISTToken):

    try:
        api_token = MISTToken
        url = MISTURL
        header = { "Content-Type": "application/json", "Authorization": f"Token {api_token}" } 
        body1 = {
        "macs": MAC_ADD
        }     
        print(MAC_ADD , "MIST function")
        res = requests.post(url, headers= header, verify=False, json= body1)
        e = f"It works {res}"
    except Exception as e:
        e = f"Error in Mist API call: {e}"

def processdes(des):
    try:
        if len(des) == 8:
            print("good to go")
            return des
    except:
        print("please enter a proper site code")
        raise TypeError
        
def extract_mac_addresses(data_dict): 
    mac_addresses = [] 
    # Adjusted regex to match MAC addresses more flexibly, including those without standard delimiters 
    mac_regex = re.compile(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{12}') 
    for entry in data_dict.get('host_entries', []): 
        # Extracting from 'host_address' 
        host_address = entry.get('host_address') 
        if host_address: found = mac_regex.findall(host_address) 
        cleaned = [re.sub('[^0-9a-fA-F]', '', addr) for addr in found]
        mac_addresses.extend(cleaned) 
       # Ensuring unique MAC addresses are returned 
    return list(set(mac_addresses)) 



    
app = Flask(__name__)
CORS(app)
@app.route('/process', methods=['POST'])

def process():
    print("\n\n\n\n\n\n\n New run")
    with open('variables.json', 'r') as config_file:
        config = json.load(config_file)
        clearpass_url = config["ClearpassURL"]
        clearpass_token = config["Clearpasstoken"]
        MISTURL = config["MISTURL"]
        MISTToken = config["MISTToken"]
        ID = config["ID"]
    data = request.get_json()
    MAC_ADD = data['macAddress']
    des = data['siteDescription']
    MAC_ADD = processMAC(MAC_ADD)
    des = processdes(des)
    MAC_list = Clearpass(MAC_ADD, des,clearpass_url,clearpass_token,ID)
    print(MAC_list)
    MAC_list = extract_mac_addresses(MAC_list)
    mist(MAC_list, MISTURL, MISTToken)
    response = {
            "status": "success",
            "message": "Data sent successfully!"
            }
    
    return jsonify(response)
@app.route('/', methods=['GET'])
def DisplayWebpage():
    return render_template(r'MACblockerfrontend.html')


if __name__ == '__main__':


    
    app.run(debug=True)
    


