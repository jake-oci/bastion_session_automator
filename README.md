This script was Authored by Jake Bloom OCI Principal Network Solution Architect. This is not an Oracle supported script. No liability from this script will be assumed and support is best effort.

# **Quickstart**

***Make sure to read the installation steps to read the "**Prerequisites**" section!***

After the Bastion Host is deployed, collect the OCID and run the python script. The script builds a SOCKS5 tunnel (HTTP traffic and SOCKS5 aware traffic). I also have a test instance that I want to SSH into, so I add the "-l" paramter to set up local forwarding.

example: python3 bastion\_session\_automator.py -b ocid1.bastion.oc1.us-chicago-1.amaaaaaac3adhhqaozfw4lv7rxtns3spojfqwf3ys3mipnn5jnahu5e7rbmq -l 10.0.1.42 22

**If you don't quite understand how SOCKS5 or Local-Forwarding works, this script does a lot of the backend work and I've described how to make it useful for you in the "Desktop Usage" section of this README.**

# **Prerequisites**

**Install Script**

- git clone [https://github.com/jake-oci/bastion\_session\_automator/](https://github.com/jake-oci/bastion_session_automator/)
    - No git on your desktop? Copy the **bastion\_session\_automator.py** file to a memorable place.
- Install the OCI SDK
    - Run "pip3 install oci" for a global installation
    - Go to https://pypi.org/project/oci/ for more details and installation methods.

**Create an API key**

- In the OCI Console, go to **Identity & Security->Users->User Details->API Key->Add API Key**
    - Copy the pre-generated configuration and add it to **\[USER_PATH\]/.oci/config** on your desktop.
    - Download the private key to a safe place (such as the .oci folder), and update the pre-generated configuration with the filepath of the .PEM file.

**Deploy a SOCKS5 Bastion Host**

- In the OCI Console, go to **Identity & Security -> Bastion -> Create Bastion**
    - Set a Memorable Name
    - Set an existing VCN and subnet you want to access.
        - If security lists/NSG's all for it, this Bastion will be able to reach everything in the VCN it's deployed to
    - Check "Enable FQDN Support and SOCKS5"
    - CIDR block allow list
        - "0.0.0.0/0" if you are testing.
        - "1.0.0.0/32" or another fake IP if you want the script to automatically update the allow list based on the user's public IP.

# **Features**

## **Fastest Connection to OCI**

- Start a new connection to OCI in less than 10 seconds. Purely automated connection to your OCI Infrastructure.
- Overcomes the session timeout problem in 2 ways.

1.  1.  Running the script will build a new session in less than 10 seconds, an order of magnitude faster than going through the UI.
    2.  There is an option to run the script indefinitely (-r on the CLI) rebuilding inactive Bastion Sessions until the script is closed, or a failure is detected.

## **Practical Security**

- There are 2 distinct benefits on enhancing security for Bastion Sessions.
    
    - An Ephemeral RSA key-pair is created every time you run the script, which means you never use the same key to encrypt your traffic over the internet.
        - No more 0.0.0.0/0 in your access list because your users are coming from dynamic public IP space! Automatically adds your public IP address to the Bastion Host CIDR allow-list making it easy to follow best practices.
            - NOTE: If the script detects a 0.0.0.0/0 in the allow list, it will assume you don't want to modify the allow list and bypass this feature.

## **Simple VPN**

- Dozens of users can use this script to connect into common OCI infrastructure if you account for oversubscription. The Bastion Host is capable of 20 concurrent sessions.

## **Cloud Native**

- Bastion is a free service included with your OCI tenancy
- Bastion integrates with OCI IAM.
    - Restrictions can be made based on the user's role
    - Removing a user from the IAM policy will revoke their ability to connect to OCI.

## **Other Benefits**

- **Private DNS Resolution** \- Take full advantage of OCI's private DNS by tunneling client DNS traffic to an OCI resolver.
- **Multi-Region Aware** - Connect to a Bastion anywhere in the world and the script will update your configuration profile to match that region.
- **Crossplatform -** Even Windows has SSH in Powershell. All Operating Systems Welcome.
- **Scripts can be run simultaneously** \- Connect to multiple Bastion hosts at the same time.

# Script Usage

### USAGE:

python3 bastion\_session\_automator.py -b BASTION_OCID

### **CLI Switches:**

-b/--bastion_ocid: (Required) The Bastion Host OCID

-r/--run-forever: (Optional) Create new bastion sessions forever. There will be a 5-10 second pause in connectivity between sessions.

-l/--local-connections: (Optional) Create a local forwarding session to an OCI instance using the private IP and destination port you want to connect to. (For nonSOCKS5 traffic such as RDP)

### **Example With Optional Commands:**

example: python3 bastion\_session\_automator.py -b ocid1.bastion.oc1.us-chicago-1.amaaaaaac3adhhqaozfw4lv7rxtns3spojfqwf3ys3mipnn5jnahu5e7rbmq -r -l 10.0.0.100 3389 -l 10.0.101.45 22

description: This will connect to the bastion, run the script indefinitely, and create local forwarding sessions to 10.0.0.100 for RDP (port 3389) and 10.0.101.45 for SSH (port 22)

### **Notes on Usage:**

Variables can also be hard-set in the script if you choose not to run them through the CLI. CLI switches will override the parameters that are set within the script.

# Desktop Usage

## This Script Supports 2 Connection Types:

## **SOCKS5**

The script will always create a SOCKS5 connection, as it's foundational both to both of the connection types. When you run the script, you will see an output similar such as this.

**SOCKS5 PROXY &lt;--MAPPED TO--&gt; localhost:25844**

localhost:25844 is where you need to set up your SOCKS5 endpoint, to forward traffic to OCI.

There are two ways to test this.

1.  Go to your web browser and add a SOCKS5 configuration. Add the localhost:portnumber (localhost:25844) that the script provides and optionally add the ability to tunnel DNS over SOCKS5. Now all HTTP applications in OCI are accessible directly from your client using the IP address or DNS name and port number!
2.  For cURL capable shells, run "curl --socks5 localhost:25844 ifconfig.me". The output will show the public IP address

## **Local Forwarding**

Some applications are not SOCKS5 aware. For these types of applications, a local forwarding session will need to be set up.Keep in mind for any localforwarding you will need to specific "localhost" as the IP address, and the random port number, since default ports will not be mapped.

Here are two working examples.

1.  If I need to get to an RDP server with an OCI IP address of 10.100.0.240, you will run this command in the script. 10.100.0.240 is the OCI IP, and 3389 is the default port for RDP.
    - example: python3 bastion\_session\_automator.py -b BASTION_OCID -l 10.100.0.240 3389
        - The script will map 10.100.0.240 3389 to a localhost and port number, like below:
            - **10.100.0.240:3389 &lt;--MAPPED TO--&gt; localhost:41677**
        - To RDP to this OCI instance, all you need to do is use "localhost" as the hostname/ipaddress and 41677 as the port number.
2.  SSH into OCI IP 10.100.0.10 22
    - example: python3 bastion\_session\_automator.py -b BASTION_OCID -l 10.100.0.10 22
        - The script will map 10.100.0.10 22 to a localhost and port number, like below:
            - **10.100.0.240:3389 &lt;--MAPPED TO--&gt; localhost:26867**
        - To SSH into to this OCI instance run the following command. Notice that -p specify's the mapped port, and localhost maps the OCI IP address.
            - ssh -p 26867 opc@localhost

# **Limitations/Known issues**

**Limitations:**

- This is an access server and is not intended for large file transfers or database queries. Throughput is limited to 2MB/s per session.
- For nonSOCKS5 traffic, you will need to specify the "-l" parameter in the CLI and give a destination IP and destination port to forward traffic to. If you have many hosts that don't support SOCKS5, this may start to become impractical. Consider using SSHUTTLE or true a Remote Access VPN solution to extend OCI networks to your client/desktop.
- This is a Layer 5 proxy. Tools like ping and netcat are not going to work the way they would like a Remote Access VPN.

**Known Issues:**

- Asyncio RunTime Error: When closing the script with CNTL-C, sometimes you will get a RunTime Error from the Asyncio Process. I can't determine why the error is happening, but the script exits cleanly, so it's a display issue more than anything else.
