import argparse, socket, hashlib, os, tempfile, random, time, atexit, signal, asyncio, logging, subprocess, ipaddress, urllib, sys

###Required Variables###
#user_bastion_host_ocid="ocid1.bastion.oc1.us-chicago-1.amaaaaaac3adhhqaozfw4lv7rxtns3spojfqwf3ys3mipnn5jnahu5e7rbmq" #OCID of the Bastion Host you want to create sessions with on OCI.

###Optional Variables###
#user_session_ttl=1800 #60 Minutes by default, and gives a good balance for allowing stale sessions to close and allow other users to connect to the Bastion host.
#user_local_connections=[("10.0.0.254", 8000),("10.0.1.130", 3389),("10.0.0.3", 21),("10.0.0.254", 22)] #Set OCI_PRIVATE_IP and OCI_DEST_PORT for non-SOCKS5 applications to do local forwarding.
##########################

###File Locations###
#If you're using non-standard locations, specify them here. 
#user_oci_config=r"/Users/jake/.oci/config" #OCI Configuration File that was generated from the API Key in the OCI GUI. Set this variable if you want to use a custom file and profile.
#user_oci_config_profile="DEFAULT" #Name of the configuration profile you want to use within your ~/.oci/config file. Unspecified will default to DEFAULT.
#The script automatically creates an SSH keypair every time that it's run. You can specify your own keypair here if you would like to use this instead. 
#user_public_key_path=r"/Users/jake/.ssh/id_rsa.pub" #Specify the full path of the SSH Public key.
#user_private_key_path=r"/Users/jake/.ssh/id_rsa" #Specify the full path of the SSH Private key.

### Debug Logging, Uncomment to get a lot of info
#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG) #Turn this on if you're trying to debug the script.
# Asyncio Logging
logging.getLogger('asyncio').setLevel(logging.ERROR)

#CLI Help Commands and Options
CLI=argparse.ArgumentParser(description= "Usage: python3 bastion_session_automator.py -b BASTION_HOST_OCID -l OCI_PRIVATE_IP_1 DESTINATION_PORT_1 -l OCI_PRIVATE_IP_2 DESTINATION PORT_2 -r")
CLI.add_argument("--bastion_ocid","-b", type=str,help="add your Bastion OCID")
CLI.add_argument("--run_forever", "-r", action='store_true',help="Set this flag to create bastion sessions indefinitely")
CLI.add_argument("--local_connections", "-l", type=str, action="append", nargs="+",help="USAGE: -l OCI_PRIVATE_IP OCI_PORT")
args=CLI.parse_args()
if args.bastion_ocid != None:
    user_bastion_host_ocid=args.bastion_ocid
if args.local_connections != None:
    local_connections_list=args.local_connections
    user_local_connections=[tuple(x) for x in local_connections_list]

#Verify the OCI SDK is installed on the operating system.
try: 
    import oci
except ImportError: 
    print("ERROR -- Failed to import OCI SDK. Make sure it is installed and accessible.")
    print("https://pypi.org/project/oci/")
    print("Run this command if you want to skip some reading.")
    print("pip3 install oci")
    raise SystemExit

#Make sure all required variables are set.
try:
    user_bastion_host_ocid
except NameError:
    print("ERROR -- The 'user_bastion_host_ocid' variable needs to be set, or you need to specify -b BASTION_HOST_OCID from the CLI.")
    raise SystemExit
try:
    custom_oci_config=False
    custom_oci_profile=False
    if user_oci_config is not NameError:
        if os.path.exists(user_oci_config) is False:
            print("ERROR -- Unable to reach your specified user config path.")
            print (user_oci_config)
            raise SystemExit
        custom_oci_config=True
    if user_oci_config_profile is not NameError:
        custom_oci_profile=True
except NameError:
    pass

#Make sure the user_local_connections list is syntatically correct
try:
    user_local_connections
    for ip_port_tuple in user_local_connections:
        try:
            ipaddress.ip_address(ip_port_tuple[0])
        except Exception as e:
            print(e)
            raise SystemExit
        if int(ip_port_tuple[1]) not in range(1,65535):
            print("The port number {} you provided for {} is not valid.".format(ip_port_tuple[1],ip_port_tuple[0]))
            raise SystemExit
except NameError:
    pass
#Make sure SSH (OpenSSH) is available on the Operating System
try:
    subprocess.call(["ssh"], 
    stdout=subprocess.DEVNULL, 
    stderr=subprocess.STDOUT)
    logging.info("SSH is available")
except Exception as e:
    print(e)
    print("ERROR -- OpenSSH needs to be accessible to use this script")
    print("If you are using Windows, make sure you are using 64 Bit Python and that OpenSSH is installed on your machine")
    print("You should be able to run 'ssh' and get a response from the shell.")
    raise SystemExit

###Functions
def local_port_generator():
        port_value=random.randint(20000,50000)
        return(port_value)
def port_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        port_open = s.connect_ex((ip, int(port))) == 0
        if port_open:
            s.shutdown(socket.SHUT_RDWR)
    except Exception:
        port_open = False
    s.close()
    return port_open
def generate_seed(s):
    int_values = [c for c in s if c.isdigit()]
    int_string = "".join(str(v) for v in int_values)
    hash_obj = hashlib.sha256(int_string.encode())
    hash_bytes = hash_obj.digest()
    hash_hex = hash_bytes.hex()
    hash_digits = str(int(hash_hex, 16))[:16]
    return hash_digits
def commands(type, ip_addr, remote_port, privatekey):
    local_port = local_port_generator()
    if type == "SOCKS5":
        print("SOCKS5 PROXY <--MAPPED TO--> localhost:{}".format(local_port))
        cmd = "ssh", "-i", privatekey, "-o", "identitiesOnly=yes", "-o", "HostKeyAlgorithms=ssh-rsa", "-o", "PubkeyAcceptedKeyTypes=ssh-rsa", "-o", "serveraliveinterval=60", "-o", "StrictHostKeyChecking=no", "-N", "-D", "{}:{}".format("127.0.0.1", local_port), "{}@{}".format(bastion_session_ocid, bastion_fqdn)
    if type == "LOCAL":
        print("{}:{} <--MAPPED TO--> localhost:{}".format(ip_addr, remote_port, local_port))
        cmd = ("ssh", "-i", privatekey, "-o", "identitiesOnly=yes", "-o", "HostKeyAlgorithms=ssh-rsa", "-o", "PubkeyAcceptedKeyTypes=ssh-rsa", "-o", "serveraliveinterval=60", "-o", "StrictHostKeyChecking=no", "-N", "-L", "{}:{}:{}".format(local_port, ip_addr, remote_port), "{}@{}".format(bastion_session_ocid, bastion_fqdn))
    return cmd
def cleanup():
        try:
            os.remove(ssh.privatekey_path)
        except Exception:
            pass
        try:
            os.remove(ssh.publickey_path)
        except Exception:
            pass
def exit_buddy():
    try:
        user_local_connections
    except NameError:
        print("")
        print("[Attention!] Uncomment the 'local_connections' variable or specify '-l' from the CLI to pass Non-SOCKS5 traffic.")
    cleanup()
    print("EXITING -- Bastion session is cleaned up and SSH tunnels are terminated. Run the script again to reconnect.")
    raise SystemExit

#Handles most scenarios to delete the ephemiral private and public key, if temp file does not handle it.
atexit.register(cleanup)
signal.signal(signal.SIGTERM, lambda signum, frame: cleanup())
signal.signal(signal.SIGHUP, lambda signum, frame: cleanup())


#Asynchrionous Functions
async def run_cmd(uniq,bastionocid):
    seed_set=generate_seed(uniq)
    random.seed(seed_set)
    cmd = []
    if not cmd:
        cmd.append(commands("SOCKS5",0,0,ssh.privatekey_path))
        while True:
            try:
                user_local_connections
                for (ip_addr, remote_port) in user_local_connections:
                    cmd.append(commands("LOCAL",ip_addr,remote_port,ssh.privatekey_path))
                break
            except:
                break
    await asyncio.gather(*[subprocess(cmds,bastionocid) for cmds in cmd])
async def subprocess(cmds,bastionocid):
    subprocess_errors=0
    session_ocid=""
    while subprocess_errors<15:
        if bastionocid == session_ocid:
            try:
                checkin=bastion_client.get_session(session_id=bastionocid)
                process = await asyncio.create_subprocess_exec(*cmds,
                    stdout=asyncio.subprocess.PIPE, 
                    stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await process.communicate()
                if checkin.data.lifecycle_state != "ACTIVE":
                    break
                else:
                    await asyncio.sleep(.5)
                    subprocess_errors=subprocess_errors+1
            except Exception as e:
                print("Asyncio Exception Error#1")
                print(e)
        if bastionocid != session_ocid:    
            session_ocid=bastionocid
            subprocess_errors=0
    if subprocess_errors==15:
        print("ERROR! -- There is a configuration issue with SSH. I recommend resolving the SSH issue outside of the script before continue to use it. Here is the error.")
        print("If you are seeing this error after long 'run forever' sessions, run the script again to restart.")
        process = await asyncio.create_subprocess_exec(*cmds,
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        print(stdout.decode(),stderr.decode())
        raise SystemExit

#If an SSH Keypair is specified, use and check it. If the keypair is not available, create a new one that is specific for this Bastion Session.
class ssh_keypair:
    def __init__ (self):
        self.printer=None
        try:
            self.user_public_key_path=user_public_key_path
            self.user_private_key_path=user_private_key_path
        except NameError:
            self.user_public_key_path=None
            self.user_private_key_path=None
        self.publickey=None
        self.privatekey=None
        self.publickey_path=None
        self.privatekey_path=None
        self.userset=None
        self._generate_keypair()
    def _generate_keypair(self):
        if self.user_public_key_path is None:
             self.printer=("SSH KEY -- Generating an ephemeral SSH keypair for this Bastion Session.")
        else:
            self.printer=("SSH KEY -- Using the SSH keypair that was specified in the script. Encrypted keys are not currently supported in this script.")
        if self.user_public_key_path and self.user_private_key_path:
            try:
                os.path.isfile(self.user_public_key_path)
                os.path.isfile(self.user_private_key_path)
                open_pub=open(self.user_public_key_path, 'r')
                open_priv=open(self.user_private_key_path, 'r')
                self.publickey = open_pub.read()
                self.privatekey = open_priv.read()
                self.publickey_path = self.user_public_key_path
                self.privatekey_path = self.user_private_key_path
                self.userset="True"
            except Exception as e:
                print("ERROR -- Unable to open the keypair that was manually set.")
                print("Make sure this file is assessible by the script")
                print("Unset the public and private keypaths to have the script automatically create an SSH RSA keypair.")
                print("")
                print(e)
                raise SystemExit
        else:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
            private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.OpenSSH,encryption_algorithm=serialization.NoEncryption())
            with tempfile.NamedTemporaryFile(delete=False) as private_key_file:
                os.chmod(private_key_file.name,0o600)
                private_key_file.write(private_key_bytes)
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.OpenSSH,format=serialization.PublicFormat.OpenSSH)
            priv_key_contents=private_key_bytes.decode()
            pub_key_contents=public_key_bytes.decode()
            with tempfile.NamedTemporaryFile(delete=False, prefix='') as public_key_file:
                os.symlink(public_key_file.name, private_key_file.name+str('.pub'))
                os.chmod(public_key_file.name,0o644)
                public_key_file.write(public_key_bytes)
            self.publickey = pub_key_contents
            self.privatekey = priv_key_contents
            self.publickey_path = public_key_file.name
            self.privatekey_path = private_key_file.name
ssh=ssh_keypair()
print("")
print(ssh.printer)

#Instantiate the OCI configuration, validate it, set the Bastion region and authenticate the user.
try:
    print("OCI -- Authenticating OCI User...")
    if custom_oci_config is True:
        if custom_oci_profile is True:
            oci_config = oci.config.from_file(user_oci_config,user_oci_config_profile)
        oci_config = oci.config.from_file(user_oci_config)
    else:
        oci_config = oci.config.from_file()
    oci.config.validate_config(oci_config)
    identity = oci.identity.IdentityClient(oci_config)
    #Parse Bastion OCID for Proper OCI Config Region
    bastion_region_code=user_bastion_host_ocid.split('.')[-2]
    available_regions = identity.list_regions()
    region_set=None
    for region_mapping in available_regions.data:
        region_code=region_mapping.key
        region_name=region_mapping.name
        if bastion_region_code.upper() == region_code.upper():
            oci_config["region"] = region_name
            region_set=True
        if bastion_region_code.upper() == region_name.upper():
            oci_config["region"] = region_name
            region_set=True
    if region_set is None:
        print("ERROR -- Unable to set the region for this Bastion Host. Make sure the Bastion OCID was copied properly.")
        raise SystemExit
    oci.config.validate_config(oci_config)
    print("OCI -- Connected to the {} OCI Region".format(oci_config["region"].upper()))
except Exception as e:
    print("ERROR -- There is an error with your OCI configuration file parameters")
    print("")
    print (e)
    raise SystemExit

#Start the Bastion Client
bastion_client = oci.bastion.BastionClient(oci_config)
#Ideally I can find this somewhere else to avoid an unexpected error. The OCI SDK does not show the Bastion Region FQDN, so we have to make it manually
bastion_fqdn = "host.bastion." + oci_config["region"] + ".oci.oraclecloud.com" 
if port_open(bastion_fqdn, 22) is False:
    print ("ERROR -- Unable to connect to the Bastion Host {}".format(bastion_fqdn))
    print("Verify connectivity and firewall settings to OCI.")
    raise SystemExit

#Get Bastion Host Details
bastion_host = bastion_client.get_bastion(bastion_id=user_bastion_host_ocid)
if bastion_host.data.dns_proxy_status == "DISABLED":
    print("ERROR -- This Bastion host is not capable of SOCKS5. Pick a SOCKS5 capable Bastion Host to use this script.")
    raise SystemExit

get_pubip_list=['https://v4.ident.me', 'https://ifconfig.me/', 'http://myip.dnsomatic.com']
url_set=None
for url in get_pubip_list:
    try:
        request=urllib.request.urlopen(url)
        if request.getcode() == 200:
            pub_ip=(request.read().decode('utf8'))
            if ipaddress.IPv4Address(pub_ip):
                client_public_ip=pub_ip
                url_set=True
                break
    except Exception as e:
        print(e)
        print("Unable to Get Public IP Address From {}".format(url))
        print("Trying Other URLs")
if url_set is None:
    print("ERROR -- Unable to determine your public IP address. Exiting the script.")
    raise SystemExit

#Allow List Manager
#Appends your public IP Address to the ALLOW list if you're not using an allow any (0.0.0.0/0) network.
#There is a maximum of 20 IP addresses allowed on this list, so the script reorders the list based on the most recently used public IP. 
#If the allowlist is full (20 IP's), it will drop the oldest entry. 
host_pub_ip=(ipaddress.ip_network(client_public_ip))
allowed_cidrs=bastion_host.data.client_cidr_block_allow_list
allow_all_cidrs=None

for ip_block in allowed_cidrs:
    if ipaddress.ip_address(client_public_ip) in ipaddress.ip_network(ip_block):
            if ipaddress.ip_network(ip_block) == ipaddress.ip_network("0.0.0.0/0"):
                print("Bastion Host -- CIDR ALLOW Rule '{}' will allow connectivity from PUB IP {}".format(ip_block, client_public_ip))
                allow_all_cidrs=True
if allow_all_cidrs is None:
    if len(allowed_cidrs) == 20:
        del allowed_cidrs[0]
    allow_current_ip=allowed_cidrs + [str(host_pub_ip)]
    foundcidr=None
    for ip in allowed_cidrs:
        if ip == str(host_pub_ip):
            allowed_cidrs.remove(str(host_pub_ip))
            allowed_cidrs.append(str(host_pub_ip))
            foundcidr=True
            break          
    if foundcidr is None:
        print("Bastion Host -- Your public IP address does not match any of the ALLOWED CIDRs in the Bastion Host.")
        print("Bastion Host -- This script will update the CIDR with your Public IP address and assume you have the permissions to update the Bastion Host.")
        print("Bastion Host -- If you continue to see this message after rerunning the script, you most likely don't have permissions to add your CIDR to the allow list.")
        allowed_cidrs.append(str(host_pub_ip))
    update_bastion_response = bastion_client.update_bastion(
        bastion_id=user_bastion_host_ocid,
        update_bastion_details=oci.bastion.models.UpdateBastionDetails(
        client_cidr_block_allow_list=allowed_cidrs))
    print("Bastion Host -- The Bastion Host ALLOW LIST has been configured to accept connections from {}.".format(client_public_ip))
       
active_sessions_bastion = bastion_client.list_sessions(
        bastion_id=user_bastion_host_ocid,
        session_lifecycle_state="ACTIVE")
active_bastion_sessions=(active_sessions_bastion.data)
if len(active_bastion_sessions) >= int(bastion_host.data.max_sessions_allowed*.8):
    print("Bastion Host -- Session Count is Nearing the Limit of the Bastino Host -- {}/{}".format(len(active_bastion_sessions),bastion_host.data.max_sessions_allowed))
    print("Bastion Host -- Consider adding more capacity by creating another Bastion Host.")
if len(active_bastion_sessions) == bastion_host.data.max_sessions_allowed:
    print("Bastion Host -- Bastion Host is at capacity - ACTIVE{}/TOTAL{} SESSIONS. A session needs to be freed up before you can connect to this Bastion.".format(len(active_bastion_sessions),bastion_host.data.max_sessions_allowed))
    raise SystemExit
print("Bastion Host -- {} Total Active Sessions = {}".format(bastion_host.data.name.upper(),len(active_bastion_sessions)))

#Bastion Session Details
#Create a unique session name based on the user OCID.
#I can't find a better way to do this with the bastionclient class, but it is necissary for Bastion Session management.
session_display_name=(oci_config["user"].split('.')[4])

def check_for_existing_bastion_session():
    active_sessions_user = bastion_client.list_sessions(
            bastion_id=user_bastion_host_ocid,
            display_name=session_display_name,
            session_lifecycle_state="ACTIVE")
    active_user_sessions=(active_sessions_user.data)
    if active_user_sessions != []: 
        print("Bastion Session -- Stale Bastion Session Detected. Deleting . . .")
        bastion_session_cleanup=(active_user_sessions[0].id)
        bastion_client.delete_session(session_id=bastion_session_cleanup)
    print("Bastion Session -- OCI Is Creating A Bastion Session.")
check_for_existing_bastion_session()

#Set Session TTL
try:
    user_session_ttl
    if user_session_ttl > bastion_host.data.max_session_ttl_in_seconds:
        print ("Bastion Session -- The session TTL is set for higher than what this Bastion Supports.")
        print ("Bastion Session -- Setting Session Timeout to Max Bastion Timeout, {}".format(bastion_host.data.max_session_ttl_in_seconds))
        user_session_ttl=bastion_host.data.max_session_ttl_in_seconds
except NameError:
    user_session_ttl=3600

def create_bastion_session():
    bastion_session=bastion_client.create_session(
            create_session_details=oci.bastion.models.CreateSessionDetails(
                bastion_id=user_bastion_host_ocid,
                target_resource_details=oci.bastion.models.CreateManagedSshSessionTargetResourceDetails(
                    session_type="DYNAMIC_PORT_FORWARDING"),
                    key_details=oci.bastion.models.PublicKeyDetails(
                    public_key_content=ssh.publickey),
                display_name=session_display_name,
                key_type="PUB",
                session_ttl_in_seconds=user_session_ttl))
    print("Bastion Session -- Bastion is in a CREATING status, waiting for ACTIVE.")
    while True:
        bastion_session=(bastion_client.get_session(session_id=bastion_session.data.id))
        if bastion_session.data.lifecycle_state == "CREATING":
            time.sleep(.3)
        if bastion_session.data.lifecycle_state == "ACTIVE":
            print("Bastion Session -- Bastion Session is in an {} status.".format(bastion_session.data.lifecycle_state))
            return bastion_session.data.id
            
bastion_session_ocid=create_bastion_session()


##My way of creating a hash from two static variables that are unique to each user, and then setting a seed value to get the same random numbers every time.
#This is needed for two reasons.
#1.) You don't want to run this script while another user is on the Bastion host with the same port number, that will result in dropped connections.
#2.) If you want to run the script more than once on your local machine to different Bastion hosts, you can do that and the ports should be random enough not to have a collision. 
uniquestring=(user_bastion_host_ocid + oci_config["user"]) 

#Start Building the SSH sessions.
try:
    if args.run_forever is True:
        starttime=time.time()
        print("")
        print("[Attention!]")
        print("Sessions will indefinitely be created for you in the background.")
        print("You might see a temporary disconnect while a new session is created.")
        print("")
        print("!!!KEEP THIS TERMINAL OPEN!!!")
        while True:
            try:
                session_state=bastion_client.get_session(session_id=bastion_session_ocid)
                if session_state.data.lifecycle_state == "ACTIVE":
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    asyncio.run(run_cmd(uniquestring,session_state.data.id), debug=False)
                if session_state.data.lifecycle_state != "ACTIVE":
                    print("")
                    print("Bastion Session -- Session Expired, building a new Bastion Session.")
                    bastion_host = bastion_client.get_bastion(bastion_id=user_bastion_host_ocid)
                    allowed_cidrs=bastion_host.data.client_cidr_block_allow_list
                    access_still_allowed=None
                    for ip_block in allowed_cidrs:
                        if ipaddress.ip_network(ip_block) == ipaddress.ip_network("0.0.0.0/0"):
                            access_still_allowed=True
                            break
                        if ipaddress.ip_address(client_public_ip) in ipaddress.ip_network(ip_block):
                            access_still_allowed=True
                            break
                    if access_still_allowed is None:
                        print("ERROR -- Ending this session since the Bastion Host's CIDR allowlist does not allow your public IP.")
                        print("INFO -- Rerunning this script to update the CIDR list with your public IP address")
                        raise SystemExit
                    bastion_session_ocid=create_bastion_session()
            except KeyboardInterrupt:
                runtime=(-1*(starttime-time.time()))
                if runtime> 60:
                    print("")
                    print("OCI -- The Script Ran for {:.0f} Seconds".format(runtime))
                try:
                    bastion_client.delete_session(session_id=bastion_session_ocid)
                finally:
                    exit_buddy()

    else:
        print("")
        print("!!!KEEP THIS TERMINAL OPEN!!!")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio.run(run_cmd(uniquestring,bastion_session_ocid), debug=False)
        print("")
        print("Bastion Session -- Bastion Session Expired.")
        print("Bastion Session -- The current session TTL is {} minutes".format(user_session_ttl/60))
        exit_buddy()
except KeyboardInterrupt:
    try:
        bastion_client.delete_session(session_id=bastion_session_ocid)
    finally:
        print("")
        exit_buddy()
except Exception as e:
    print("Error#2")
    print(e)
    exit_buddy()
#Version 1.0
#Authored by Jake Bloom
