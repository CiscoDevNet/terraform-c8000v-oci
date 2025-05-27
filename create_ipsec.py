# config_renderer.py
import ipaddress
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import subprocess
import logging
import argparse
import os
import sys
import socket
import time
import pexpect

def find_valid_host_mask(ip_str):
    ip = ipaddress.IPv4Address(ip_str)

    # Check from /30 (most common small subnet) down to /1
    for prefix in range(30, 0, -1):
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        if ip != network.network_address and ip != network.broadcast_address:
            return str(network.netmask)

    return None  # Could not find a usable subnet


def create_ipsec_configuration(Tunnel1_DestinationIP,Tunnel1_PSK,Tunnel2_DestinationIP,Tunnel2_PSK,IKE_Local_PublicIP):
    Tunnel1_Local_IP = "192.168.1.9" #his is the private IP address configured on the C8kv side of the first tunnel interface.
    Tunnel2_Local_IP = "192.168.1.13"#his is the private IP address configured on the C8kv side of the first tunnel interface.
    BGP_Local_ASN = "65043"
    Tunnel1_BGP_Neighbor = "192.168.1.10" #IPv4 inside tunnel interface - Oracle
    Tunnel2_BGP_Neighbor = "192.168.1.14"#IPv4 inside tunnel interface - Oracle
    SUBNET_IKE=find_valid_host_mask(IKE_Local_PublicIP)
    """Create IPsec configuration from template file by replacing placeholders with values"""
    # Create a dictionary mapping placeholders to their values
    placeholders = {
        "{{Tunnel1-DestinationIP}}": Tunnel1_DestinationIP,
        "{{Tunnel1-PSK}}": Tunnel1_PSK,
        "{{Tunnel2-DestinationIP}}": Tunnel2_DestinationIP,
        "{{Tunnel2-PSK}}": Tunnel2_PSK,
        "{{IKE-Local-PublicIP}}": IKE_Local_PublicIP,
        "{{Tunnel1-Local-IP}}": Tunnel1_Local_IP,
        "{{Tunnel2-Local-IP}}": Tunnel2_Local_IP,
        "{{BGP-Local-ASN}}": BGP_Local_ASN,
        "{{Tunnel1-BGP-Neighbor}}": Tunnel1_BGP_Neighbor,
        "{{Tunnel2-BGP-Neighbor}}": Tunnel2_BGP_Neighbor,
        "{{SUBNET_IKE}}": SUBNET_IKE
    }

    # Read the template file
    template_path = "template"
    if not os.path.exists(template_path):
        logging.error(f"Template file not found: {template_path}")
        raise FileNotFoundError(f"Template file not found: {template_path}")

    with open(template_path, "r") as file:
        config_template = file.read()

    # Replace all placeholders
    for key, value in placeholders.items():
        config_template = config_template.replace(key, value)

    # Write the rendered config to a new file
    output_path = "rendered_config_new.txt"
    with open(output_path, "w") as file:
        file.write(config_template)
    
    logging.info(f"IPsec configuration generated and saved to {output_path}")
    return output_path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("router_configuration.log"),
        logging.StreamHandler()
    ]
)

def check_ssh_port(ip_address, port=22, timeout=5, retries=3):
    """
    Check if SSH port is open using netcat or socket.
    
    Args:
        ip_address (str): IP address to check
        port (int): Port number (default: 22)
        timeout (int): Connection timeout in seconds
        retries (int): Number of connection attempts
        
    Returns:
        bool: True if port is open, False otherwise
    """
    logging.info(f"Checking SSH connectivity to {ip_address}:{port}...")
    
    # Try using netcat first if available
    for attempt in range(retries):
        try:
            # Try netcat first
            nc_cmd = ["nc", "-z", "-w", str(timeout), ip_address, str(port)]
            result = subprocess.run(
                nc_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            if result.returncode == 0:
                logging.info(f"SSH port {port} is open on {ip_address}")
                return True
            else:
                logging.warning(f"Netcat attempt {attempt+1}/{retries} failed, trying socket fallback")
                
                # Fallback to socket if netcat fails or isn't available
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    logging.info(f"SSH port {port} is open on {ip_address}")
                    return True
                else:
                    logging.warning(f"Socket attempt {attempt+1}/{retries} failed: port {port} is closed")
        except FileNotFoundError:
            # Netcat not available, try socket instead
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    logging.info(f"SSH port {port} is open on {ip_address}")
                    return True
                else:
                    logging.warning(f"Socket attempt {attempt+1}/{retries} failed: port {port} is closed")
            except Exception as e:
                logging.warning(f"Socket attempt {attempt+1}/{retries} failed: {str(e)}")
        except Exception as e:
            logging.warning(f"Connection attempt {attempt+1}/{retries} failed: {str(e)}")
        
        if attempt < retries - 1:
            time.sleep(2)
    
    logging.error(f"SSH port {port} check failed after {retries} attempts")
    return False

def generate_ssh_command(instance_console_ocid, instance_ocid, private_key_path):
    """Generates the SSH command to connect to an OCI instance via console connection."""
    proxy_command = (
        f"ssh -o \"StrictHostKeyChecking no\" -o \"UserKnownHostsFile=/dev/null\" "
        f"-o \"HostkeyAlgorithms +ssh-rsa\" -o \"PubkeyAcceptedKeyTypes +ssh-rsa\" "
        f"-i {private_key_path} -W %h:%p -p 443 "
        f"{instance_console_ocid}@instance-console.us-sanjose-1.oci.oraclecloud.com"
    )

    ssh_command = (
        f"ssh -o \"StrictHostKeyChecking no\" -o \"UserKnownHostsFile=/dev/null\" "
        f"-o \"HostkeyAlgorithms +ssh-rsa\" -o \"PubkeyAcceptedKeyTypes +ssh-rsa\" "
        f"-i {private_key_path} -o ProxyCommand='{proxy_command}' {instance_ocid}"
    )

    return ssh_command

def enable_admin_user(instance_ip, username, private_key_path, admin_password):
    """
    Connect to the instance via SSH and configure an admin user.

    Args:
        instance_ip (str): IP address of the instance
        username (str): SSH username
        private_key_path (str): Path to the SSH private key
        admin_password (str): Password for the new admin user

    Returns:
        bool: True if command was executed successfully
    """
    logging.info(f"Connecting to {instance_ip} via SSH to configure admin user...")
    
    # Create the SSH command
    connection_string = (
    f"ssh -o StrictHostKeyChecking=no "
    f"-o UserKnownHostsFile=/dev/null "
    f"-i {private_key_path} {username}@{instance_ip}"
    )

    logging.info("Formatted SSH connection string:")
    logging.info(connection_string)
    
    try:
        child = pexpect.spawn(connection_string, timeout=300, encoding='utf-8')
        
        # Wait for router prompt
        child.expect(r"#", timeout=100)
        
        # Enter configuration mode
        logging.info("Entering configuration mode")
        child.sendline("configure terminal")
        child.expect(r"\(config\)#")
        
        # Add admin user
        logging.info("Adding admin user")
        child.sendline(f"username sys_admin privilege 15 secret {admin_password}")
        child.expect(r"\(config\)#")
        
        # Exit configuration mode
        logging.info("Exiting configuration mode")
        child.sendline("exit")
        child.expect(r"#")
        
        # Save configuration
        logging.info("Saving configuration")
        child.sendline("write memory")
        child.expect(r"\[OK\]")
        
        logging.info("Admin user configured successfully")
        return True
        
    except pexpect.exceptions.TIMEOUT as e:
        logging.error(f"Timeout occurred: {e}")
        raise
    except pexpect.exceptions.EOF as e:
        logging.error(f"Unexpected end of file: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        raise
    finally:
        if 'child' in locals():
            child.close()

def check_and_activate_license(instance_ip, username, private_key_path):
    """
    Connect to the instance via SSH, check if IKEv2 is available, and activate license if needed.

    Args:
        instance_ip (str): IP address of the instance
        username (str): SSH username
        private_key_path (str): Path to the SSH private key

    Returns:
        bool: True if license is already active or was successfully activated
    """
    logging.info(f"Connecting to {instance_ip} via SSH to check license status...")
    
    # Create the SSH command
    connection_string = (
    f"ssh -o StrictHostKeyChecking=no "
    f"-o UserKnownHostsFile=/dev/null "
    f"-i {private_key_path} {username}@{instance_ip}"
    )

    logging.info("Formatted SSH connection string:")
    logging.info(connection_string)
    
    try:
        child = pexpect.spawn(connection_string, timeout=300, encoding='utf-8')
        
        # Wait for router prompt
        child.expect(r"#", timeout=100)
        
        # Enter configuration mode
        logging.info("Entering configuration mode to check if IKEv2 is available")
        child.sendline("configure terminal")
        child.expect(r"\(config\)#")
        
        # Check if IKEv2 is available
        logging.info("Checking if IKEv2 is available")
        child.sendline("crypto ikev2 ?")
        
        i = child.expect([r"% Invalid input detected", r"proposal", r"cookie", r"\(config\)#"], timeout=30)
        
        if i in [1, 2]:  # IKEv2 is available
            logging.info("IKEv2 is available. License is already activated.")
            
            # Exit configuration mode
            logging.info("Exiting configuration mode")
            child.sendline("end")
            child.expect(r"#")
            
            return True
        else:
            # IKEv2 is not available, need to activate license
            logging.info("IKEv2 is not available. Need to activate license.")
            
            # License boot level
            logging.info("Step 1: Activating license")
            child.sendline("license boot level network-advantage addon dna-advantage")
            child.expect(r"\(config\)#")
            
            # Exit configuration mode
            logging.info("Exiting configuration mode")
            child.sendline("exit")
            child.expect(r"#")
            
            # Save configuration
            logging.info("Step 2: Saving configuration")
            child.sendline("write memory")
            child.expect(r"\[OK\]")
            child.expect(r"#")
            
            # Reload the router
            logging.info("Step 3: Reloading the router")
            child.sendline("reload")
            
            # Handle reload confirmation
            i = child.expect([r"Proceed with reload\? \[confirm\]", r"System configuration has been modified. Save\? \[yes/no\]"], timeout=30)
            if i == 1:
                child.sendline("yes")
                child.expect(r"Proceed with reload\? \[confirm\]", timeout=30)
            
            # Confirm reload
            child.sendline("")
            
            logging.info("Router is reloading. Connection will be lost.")
            return True
        
    except pexpect.exceptions.TIMEOUT as e:
        logging.error(f"Timeout occurred: {e}")
        raise
    except pexpect.exceptions.EOF as e:
        logging.error(f"Connection closed unexpectedly: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        raise
    finally:
        if 'child' in locals():
            child.close()

def check_ssh_key_file(private_key_path):
    """
    Check if the SSH private key file exists and has the correct permissions.
    
    Args:
        private_key_path (str): Path to the SSH private key file
        
    Returns:
        bool: True if the file exists and has correct permissions, False otherwise
    """
    logging.info(f"Checking SSH private key file: {private_key_path}")
    
    # Check if the file exists
    if not os.path.isfile(private_key_path):
        logging.error(f"SSH private key file not found: {private_key_path}")
        return False
    
    # Check file permissions
    file_permissions = os.stat(private_key_path).st_mode & 0o777
    
    # SSH requires private key files to be readable only by the owner (0600 or 0400)
    if file_permissions & 0o077:  # Check if group or others have any permissions
        logging.error(f"SSH private key file has incorrect permissions: {oct(file_permissions)}")
        logging.error(f"Permissions should be 0600 (readable only by owner)")
        
        # Try to fix permissions
        try:
            logging.info(f"Attempting to fix permissions on: {private_key_path}")
            os.chmod(private_key_path, 0o600)
            new_permissions = os.stat(private_key_path).st_mode & 0o777
            logging.info(f"Changed permissions from {oct(file_permissions)} to {oct(new_permissions)}")
            return True
        except Exception as e:
            logging.error(f"Failed to fix permissions: {str(e)}")
            return False
    else:
        logging.info(f"SSH private key file has correct permissions: {oct(file_permissions)}")
        return True

def apply_ipsec_config(instance_ip, username, private_key_path, config_file_path):
    """
    Connect to the instance via SSH and apply the IPsec configuration.

    Args:
        instance_ip (str): IP address of the instance
        username (str): SSH username
        private_key_path (str): Path to the SSH private key
        config_file_path (str): Path to the IPsec configuration file

    Returns:
        bool: True if configuration was applied successfully
    """
    logging.info(f"Connecting to {instance_ip} via SSH to apply IPsec configuration...")
    
    # Read the configuration file
    with open(config_file_path, "r") as file:
        config_lines = file.readlines()
    
    # Create the SSH command
    connection_string = (
    f"ssh -o StrictHostKeyChecking=no "
    f"-o UserKnownHostsFile=/dev/null "
    f"-i {private_key_path} {username}@{instance_ip}"
    )

    logging.info("Formatted SSH connection string:")
    logging.info(connection_string)
    check_ssh_port(instance_ip,22,5,4)
    try:
        child = pexpect.spawn(connection_string, timeout=300, encoding='utf-8')
        
        # Wait for router prompt
        child.expect(r"#", timeout=100)
        
        # Enter configuration mode
        logging.info("Entering configuration mode")
        child.sendline("configure terminal")
        child.expect(r"\(config\)#")
        
        # Apply each line of the configuration
        logging.info("Applying IPsec configuration...")
        for line in config_lines:
            line = line.strip()
            if line:
                child.sendline(line)
                # Use a more flexible expect pattern to handle different prompts
                child.expect([r"\(config.*\)#", r"#"], timeout=10)
        
        # Exit configuration mode
        logging.info("Exiting configuration mode")
        child.sendline("end")
        child.expect(r"#")
        
        # Save configuration
        logging.info("Saving configuration")
        child.sendline("write memory")
        child.expect(r"\[OK\]")
        
        logging.info("IPsec configuration applied successfully")
        return True
        
    except pexpect.exceptions.TIMEOUT as e:
        logging.error(f"Timeout occurred: {e}")
        raise
    except pexpect.exceptions.EOF as e:
        logging.error(f"Unexpected end of file: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        raise
    finally:
        if 'child' in locals():
            child.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure IPsec connections")

    parser.add_argument("--username", required=True, help="Username for the remote server")
    parser.add_argument("--ip", required=True, help="IP address of the remote server")
    parser.add_argument("--key", required=True, help="Path to the SSH private key")
    parser.add_argument("--password", help="Password for authentication (optional)")

    parser.add_argument("--tunnel1-destination-ip", required=True, help="Tunnel 1 Oracle VPN IP address")
    parser.add_argument("--tunnel1-psk", required=True, help="Tunnel 1 Pre-Shared Key")
    parser.add_argument("--tunnel2-destination-ip", required=True, help="Tunnel 2 Oracle VPN IP address")
    parser.add_argument("--tunnel2-psk", required=True, help="Tunnel 2 Pre-Shared Key")

    args = parser.parse_args()

    # Assigning the parsed values to variables
    Tunnel1_DestinationIP = args.tunnel1_destination_ip
    Tunnel1_PSK = args.tunnel1_psk
    Tunnel2_DestinationIP = args.tunnel2_destination_ip
    Tunnel2_PSK = args.tunnel2_psk
    IKE_Local_PublicIP = args.ip
    
    try:
        # Check SSH key file before any SSH operations
        logging.info("Step 0: Checking SSH private key file...")
        if not check_ssh_key_file(args.key):
            logging.error("SSH private key file check failed. Please ensure the file exists and has correct permissions (0600).")
            sys.exit(1)
            
        # Step 1: Enable admin user
        logging.info("Step 1: Enabling admin user...")
        enable_admin_user(instance_ip=args.ip, username=args.username, private_key_path=args.key, admin_password=args.password)
        
        # Step 2: Check and activate license if needed
        logging.info("Step 2: Checking license status...")
        license_activation_result = check_and_activate_license(instance_ip=args.ip, username=args.username, private_key_path=args.key)
        
        # If license was newly activated, wait for router to reboot
        if license_activation_result:
            need_to_wait = True
            
            # Try to establish SSH connection to check if we need to wait for reboot
            try:
                # Create a quick SSH connection to see if router is still accessible
                connection_string = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {args.key} {args.username}@{args.ip}"
                ssh_process = subprocess.Popen(
                    connection_string, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                time.sleep(5)
                
                if ssh_process.poll() is None:  # Process still running - connection established
                    # Connection successful, no need to wait
                    logging.info("Router is still accessible - no reboot occurred.")
                    need_to_wait = False
                    ssh_process.terminate()
            except Exception:
                # Connection failed, likely due to ongoing reboot
                pass
                
            if need_to_wait:
                # Step 3: Wait for router to come back online
                logging.info("Step 3: Waiting for router to come back online...")
                if not check_ssh_port(args.ip, 22, 5, 44):
                    logging.error("Router did not come back online after reload")
                    sys.exit(1)
                
                # Give SSH service time to start fully
                logging.info("Router is back online. Waiting for SSH service to start fully...")
                time.sleep(30)
        
        # Step 4: Generate IPsec configuration
        logging.info("Step 4: Generating IPsec configuration...")
        config_file_path = create_ipsec_configuration(Tunnel1_DestinationIP=Tunnel1_DestinationIP, 
                                                      Tunnel1_PSK=Tunnel1_PSK, 
                                                      Tunnel2_PSK=Tunnel2_PSK, 
                                                      Tunnel2_DestinationIP=Tunnel2_DestinationIP,
                                                      IKE_Local_PublicIP=IKE_Local_PublicIP
                                                      )
        
        # Step 5: Apply IPsec configuration
        logging.info("Step 5: Applying IPsec configuration...")
        apply_ipsec_config(instance_ip=args.ip, username=args.username, private_key_path=args.key, config_file_path=config_file_path)
        
        logging.info("All operations completed successfully!")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Operation failed: {str(e)}")
        sys.exit(1)
