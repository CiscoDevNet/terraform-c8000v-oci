import paramiko
import time
import pexpect
import logging
import argparse
import os
from scp import SCPClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bootstrap_config.log"),
        logging.StreamHandler()
    ]
)


def safe_decode(output):
    """Safely decode the output, handling NoneType."""
    if output is None:
        return "<No Output>"
    return output.decode('utf-8', errors='ignore')


def scp_file(hostname, password, private_key_name, local_path, remote_path):
    """
    Transfer bootstrap file to remote host using SCP.
    """
    username = "sys_admin"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
    try:
        ssh.connect(
            hostname=hostname,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
            banner_timeout=200,
        )
        logging.info("file transfer started")
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(local_path, remote_path)
            logging.info(f"File transferred successfully to {hostname}.")

    except paramiko.AuthenticationException as e:
        logging.error(f"Authentication failed for {username}@{hostname}.")
        raise e

    except FileNotFoundError as e:
        logging.error(f"File not found: {local_path}.")
        raise e

    except Exception as e:
        logging.error(f"An error occurred while transferring the file to {hostname}.")
        raise e

    finally:
        ssh.close()

def generate_ssh_command(instance_console_ocid, instance_ocid, private_key_path):
    """Generates the SSH command to connect to an OCI instance."""
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

def establish_connection(hostname, password, private_key_name, local_path, instance_ocid, instance_console_ocid):
    """
    Establish a secure connection to the remote host and transfer the bootstrap file.
    """
    if not os.path.isfile(private_key_name):
        raise FileNotFoundError(f"Private key file not found: {private_key_name}")

    # Create the connection string
    connection_string = generate_ssh_command(instance_console_ocid, instance_ocid, private_key_name)
    logging.info("Formatted SSH connection string:")
    logging.info(connection_string)
    logging.info(f"Attempting to connect to {hostname}...")
    try:
        child = pexpect.spawn(connection_string, timeout=500, encoding='utf-8')
        child.logfile = open("connection_log.txt", "w")  # Log all session output

        # Wait for "Would you like to enter the initial configuration dialog?"
        child.expect(r"Would you like to enter the initial configuration dialog\? \[yes/no\]:", timeout=200)
        child.sendline("no")

        # Handle enable secret prompts
        child.expect(r"Enter enable secret:")
        child.sendline(password)
        child.expect(r"Confirm enable secret:")
        child.sendline(password)

        # Handle initial mode selection
        child.expect(r"Enter your selection \[2\]:")
        child.sendline("2")

        child.expect(r"Press RETURN to get started!")

        child.sendline("\r")
        child.expect(r"Router>")

        # Privileged EXEC mode
        child.sendline("enable")
        child.expect(r"Password:")
        child.sendline(password)
        child.expect(r"#")


        # Enter configuration mode and configure settings
        child.sendline("configure terminal")
        child.expect(r"\(config\)#")
        child.sendline(f"username sys_admin privilege 15 secret {password}")
        child.expect(r"\(config\)#")
        child.sendline("line vty 0 15")
        child.expect(r"\(config-line\)#")
        child.sendline("login local")
        child.expect(r"\(config-line\)#")
        child.sendline("transport input ssh")
        child.expect(r"\(config-line\)#")
        child.sendline("exit")
        child.expect(r"\(config\)#")
        child.sendline("ip scp server enable")
        child.expect(r"\(config\)#")
        child.sendline("exit")
        child.expect(r"#")

        # Save configuration
        child.sendline("write memory")
        child.expect(r"#")

        # Wait for the configuration to be saved
        time.sleep(10)

        # Transfer file via SCP
        remote_path = f"/bootflash:/{os.path.basename(local_path)}"
        scp_file(hostname, password, private_key_name, local_path, remote_path)

        logging.info("Configuration completed successfully.")
    except pexpect.exceptions.TIMEOUT as e:
        logging.error(f"Timeout occurred: {e}")
    except pexpect.exceptions.EOF as e:
        logging.error(f"Unexpected end of file: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        if child:
            child.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Establish a secure connection.")
    parser.add_argument("--hostname", required=True, help="The hostname to connect to.")
    parser.add_argument("--password", required=True, help="The password for authentication.")
    parser.add_argument("--local_path", required=True, help="The local path to save data.")
    parser.add_argument("--instance-id", required=True, help="The OCID of the instance.")
    parser.add_argument("--console-id", required=True, help="The OCID for the instance console.")
    parser.add_argument("--private-key", required=True, help="The private key file path.")

    args = parser.parse_args()

    establish_connection(
        hostname=args.hostname,
        password=args.password,
        local_path=args.local_path,
        instance_ocid=args.instance_id,
        private_key_name=args.private_key,
        instance_console_ocid=args.console_id
    )
