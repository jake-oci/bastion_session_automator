This script was Authored by Jake Bloom OCI Principal Network Solution Architect. This is not an Oracle supported script. No liability from this script will be assumed and support is best effort.

# bastion_session_automator
Automate OCI's Bastion Service For A Cross-Platform Pseudo VPN

# To-Do
This script is not yet ready for prime time. Still need to do some work.
1.) Move global variables out of the script - worked great for building the program, but shouldn't be in the final script. Will be utilizing classes.
2.) Does not check if the Bastion Host is SOCKS5 capable. This might cause problems.
3.) Asyncio has an unhandled loop exception bug that I need to squash.
4.) Add -o Identityfile option to avoid using the default identity file.

# How do I make this script work?
0.) Install the OCI SDK - https://pypi.org/project/oci/
You can run "pip3 install oci" if you are not concerned about running in a virtual environment. 

1.) Download the script and save it to a file, or gitclone to your director bastion_session_automator.py

2.) Add an API key to your ~/.oci/config file
Identity->Users->User Details->API Key->Add API Key
Download private key, and add it to the .oci folder. You will reference the full file path in your config file under the "key_file" config line.

3.) Build a SOCKS5 Bastion Host in OCI, and grab the OCID

4.) Run the script

# Usage
python3 bastion_session_automator.py -b BASTION_OCID

Optional Commands
--run-forever: 
Create new bastion sessions forever, and connect to them. There will be a 5-10 second pause in connectivity between sessions. 

--local-connections or -l: 
Create a local forwarding session to an OCI instance using the private IP and destination port you want to connect to.

An example of a full command. This will connect to the bastion, run the script indefinitely, and create local forwarding sessions to 10.0.0.100 for RDP (port 3389) and 10.0.101.45 for SSH (port 22)

python3 bastion_session_automator.py -b ocid1.bastion.oc1.us-chicago-1.amaaaaaac3adhhqaozfw4lv7rxtns3spojfqwf3ys3mipnn5jnahu5e7rbmq --run-forever -l 10.0.0.100 3389 -l 10.0.101.45 22

Variables can also be hard-set in the script if you choose not to run them through the CLI. You can run this script multiple times to connect to different bastions in the same or different regions. The script has intelligence built into to authenticate into the region where the Bastion Host resides.
