# Terraform for Catalyst 8000V in Orcale Cloud 

This terraform deploys a pair (or more) of Catalyst 8000V, OCI Dynamic Routing Gateway (DRG) and BGP session between them. Curently, the script uses private market place offering for wide field testing. Once the image for C8000V in OCI is public,the script will be updated accordignly. 

Refer to this YouTube guide for visual instruction on the script use: https://youtu.be/rYP_ix0rFZ0
<!-- BEGIN_TF_DOCS -->
## Modules

### VCN Module

This module creates a Virtual Cloud Network (VCN) with the following resources:

*   **oci_core_vcn:** The VCN itself.
*   **oci_core_route_table:** A default route table.
*   **oci_core_subnet:** Subnets for VPN (vpn0 and vpn512).
*   **oci_core_internet_gateway:** An Internet Gateway.
*   **oci_core_security_list:** A security list to control traffic.

**Variables:**

| Name                              | Description                                                    | Type           | Default          | Required |
| :-------------------------------- | :------------------------------------------------------------- | :------------- | :--------------- | :------- |
| compartment_ocid                  | The OCID of the compartment where resources will be created. | `string`       | -                | yes      |
| vcn_cidr_block                    | The CIDR block for the VCN.                                  | `string`       | `10.200.0.0/16`  | no       |
| vcn_name                          | The name of the VCN.                                         | `string`       | `OCI-SDWAN-VCN`  | no       |
| subnet_vpn0_cidr_block            | The CIDR block for the VPN0 subnet.                          | `string`       | `10.200.1.0/24`  | no       |
| subnet_vpn0_name                  | The name for the VPN0 subnet.                               | `string`       | `C8KV-VPN0`      | no       |
| subnet_vpn512_cidr_block          | The CIDR block for the VPN512 subnet.                        | `string`       | `10.200.0.0/24`  | no       |
| subnet_vpn512_name                | The name for the VPN512 subnet.                              | `string`       | `C8KV-VPN512`    | no       |
| ig_name                           | The name for the Internet Gateway.                          | `string`       | `OCI-SDWAN-IG`   | no       |
| enable_flag                       | Flag to enable or disable resource creation.                 | `bool`         | `true`           | no       |
| default_route_table_destination_ip | Default route table destination IP.                          | `string`       | `0.0.0.0/0`      | no       |
| ingress_source_ip                 | Ingress source IP for firewall rules.                        | `string`       | `0.0.0.0/0`      | no       |
| egress_destination_ip             | Egress destination IP.                                      | `string`       | `0.0.0.0/0`      | no       |
| allowed_ports_tcp                 | List of TCP ports to allow for ingress.                     | `list(number)` | `[22, 80, 443, 12346, 12366, 12386, 12406, 12426]` | no       |
| allowed_ports_udp                 | List of UDP ports to allow for ingress.                     | `list(number)` | `[500, 4500]`   | no       |

**Outputs:**

| Name            | Description                                      |
| :-------------- | :----------------------------------------------- |
| `vcn_id`        | The OCID of the created VCN.                      |
| `subnet_vpn0_id` | The OCID of the created VPN0 subnet. |

### CPE Module

This module creates a Customer-Premises Equipment (CPE) resource.

*   **oci_core_cpe:** The CPE resource.
*   **oci_core_cpe_device_shapes:** Data source to list available CPE device shapes.

**Variables:**

| Name               | Description                                                                                             | Type      | Default    | Required |
| :----------------- | :------------------------------------------------------------------------------------------------------ | :-------- | :--------- | :------- |
| `compartment_ocid` | The OCID of the compartment where the CPE will be created.                                             | `string`  | -          | yes      |
| `cpe_display_name` | The display name for the CPE.                                                                          | `string`  | `c8kv-cpe`  | no       |
| `ip_address`       | The public IP address of the CPE.                                                                       | `string`  | -          | yes      |
| `is_private`       | A boolean indicating whether the CPE uses a private IP address (true) or a public IP address (false). | `bool`    | `false`    | no       |
| `device_shape_index` | The index of the CPE device shape to use from the list of available shapes.                           | `number` | `8`        | no       |

**Outputs:**

| Name                               | Description                                              |
| :--------------------------------- | :------------------------------------------------------- |
| `oci_core_cpe_device_shapes_list` | List of available CPE device shapes.                    |
| `cpe_id`                           | The OCID of the created CPE.                            |

### Custom VM Module

This module creates custom VM instances.

*   **oci_core_instance:** The VM instances.

**Variables:**

| Name                  | Description                                                                                  | Type     | Default                  | Required |
| :-------------------- | :------------------------------------------------------------------------------------------- | :------- | :----------------------- | :------- |
| `availability_domain` | The availability domain where the instance will be launched.                               | `string`  | `BFeX:US-SANJOSE-1-AD-1` | no       |
| `compartment_ocid`    | The OCID of the compartment where the instance will be created.                             | `string`  | -                        | yes      |
| `instance_shape`      | The shape of the instance (e.g., VM.Standard.E3.Flex).                                     | `string`  | `VM.Standard.E3.Flex`    | no       |
| `source_id`           | The OCID of the custom image to use for the instance.                                      | `string`  | -                        | yes      |
| `display_name`        | The display name for the instance.                                                          | `string`  | `C8Kv2-Instance`         | no       |
| `ocpus`               | The number of OCPUs to allocate to the instance (used with flexible shapes).                | `number`  | `2`                      | no       |
| `memory_in_gbs`       | The amount of memory (in GB) to allocate to the instance (used with flexible shapes).       | `number`  | `8`                      | no       |
| `assign_public_ip`    | Whether to assign a public IP to the instance's primary VNIC.                              | `bool`    | `true`                   | no       |
| `source_type`         | The type of source to use for the instance, typically 'image'.                             | `string`  | `image`                  | no       |
| `subnet_id`           | The OCID of the subnet in which the instance's primary VNIC should be created.             | `string` | -                        | yes      |
| `ssh_key_file_path`   | The path to the SSH public key file that will be added to the instance for authorized access. | `string`  | -                        | yes      |
| `instance_count`      | The number of instances to create                                                           | `number` | `2`                      | no       |
| `hostname`            | The hostname to connect to.                                                                 | `string`  | -                        | yes      |
| `password`            | The password for authentication.                                                            | `string`  | -                        | yes      |
| `key_filename`        | The path to the key file.                                                                 | `string`  | -                        | yes      |
| `local_path`          | The local path to save data.                                                               | `string`  | -                        | yes      |

**Outputs:**

| Name           | Description                               |
| :------------- | :---------------------------------------- |
| `instance_ids` | The IDs of the created instances. |

### DRG Module

This module creates a Dynamic Routing Gateway (DRG) and related resources for IPSec VPN connectivity.

*   **oci_core_drg:** The DRG.
*   **oci_core_drg_route_table:** DRG route tables for VCN and IPSec attachments.
*   **oci_core_drg_attachment:** Attaches the VCN to the DRG.
*   **oci_core_ipsec:** The IPSec connection to the CPE.
*   **oci_core_ipsec_connection_tunnel_management:** Configures the IPSec tunnels.
*   **data "oci_core_ipsec_connection_tunnels" "tunnels"** Fetches IPSec tunnel details

**Variables:**

| Name                              | Description                                                                     | Type     | Default                  | Required |
| :-------------------------------- | :------------------------------------------------------------------------------ | :------- | :----------------------- | :------- |
| `compartment_ocid`                | The OCID of the compartment where the DRG will be created.                     | `string`  | -                        | yes      |
| `drg_display_name`                | Display name for the DRG.                                                      | `string`  | `c8kv-drg`                | no       |
| `vcn_id`                          | The OCID of the VCN to attach to the DRG.                                     | `string`  | -                        | yes      |
| `cpe_id`                          | The OCID of the Customer Premises Equipment (CPE) to use for the IPSec connection. | `string`  | -                        | yes      |
| `ipsec_display_name`              | Display name for the IPSec connection.                                        | `string`  | `c8kv-IPSec`              | no       |
| `static_routes`                   | Static routes to configure on the IPSec connection.                            | `list(string)` | `["0.0.0.0/0"]`          | no       |
| `routing`                         | Routing type for the IPSec tunnels (e.g., BGP, STATIC).                        | `string`  | `BGP`                    | no       |
| `oracle_can_initiate`             | Whether Oracle can initiate the connection (INITIATOR_OR_RESPONDER).           | `string`  | `INITIATOR_OR_RESPONDER` | no       |
| `nat_translation_enabled`         | Whether NAT translation is enabled for the IPSec tunnels.                      | `string`  | `ENABLED`                | no       |
| `customer_bgp_asn`                | Customer BGP Autonomous System Number (ASN).                                  | `string`  | -                        | yes      |
| `customer_interface_ip_tunnel1`  | Customer interface IP for Tunnel 1 (must be a /30 or /31).                     | `string`  | -                        | yes      |
| `oracle_interface_ip_tunnel1`    | Oracle interface IP for Tunnel 1 (must be a /30 or /31).                       | `string`  | -                        | yes      |
| `customer_interface_ip_tunnel2`  | Customer interface IP for Tunnel 2 (must be a /30 or /31).                     | `string`  | -                        | yes      |
| `oracle_interface_ip_tunnel2`    | Oracle interface IP for Tunnel 2 (must be a /30 or /31).                       | `string`  | -                        | yes      |
| `tunnel1_display_name`           | Display name for Tunnel 1.                                                     | `string`  | `Tunnel1-to-DRG`         | no       |
| `tunnel2_display_name`           | Display name for Tunnel 2.                                                     | `string`  | `Tunnel2-to-DRG`         | no       |
| `phase_one_auth_algorithm`        | Phase 1 authentication algorithm (e.g., SHA2_256).                            | `string`  | `SHA2_256`               | no       |
| `phase_one_dh_group`              | Phase 1 Diffie-Hellman group (e.g., GROUP14).                                 | `string`  | `GROUP14`                | no       |
| `phase_one_encryption_algorithm`  | Phase 1 encryption algorithm (e.g., AES_256_CBC).                            | `string`  | `AES_256_CBC`            | no       |
| `phase_one_lifetime`              | Phase 1 lifetime in seconds (e.g., 28800).                                    | `number`  | `28800`                  | no       |
| `phase_two_encryption_algorithm`  | Phase 2 encryption algorithm (e.g., AES_256_GCM).                            | `string`  | `AES_256_GCM`            | no       |
| `phase_two_dh_group`              | Phase 2 Diffie-Hellman group (e.g., GROUP20).                                 | `string`  | `GROUP20`                | no       |
| `phase_two_lifetime`              | Phase 2 lifetime in seconds (e.g., 3600).                                    | `number`  | `3600`                  | no       |
| `ike_version`                     | IKE version for the IPSec tunnels (e.g., V2).                                | `string`  | `V2`                     | no       |

**Outputs:**

| Name                          | Description                                          |
| :---------------------------- | :--------------------------------------------------- |
| `drg_id`                      | The OCID of the created DRG.                          |
| `drg_route_table_for_vcn_id` | The OCID of the route table for VCN attachments.     |
| `drg_route_table_for_ipsec_id` | The OCID of the route table for IPSec attachments.   |
| `drg_vcn_attachment_id`      | The OCID of the VCN attachment.                      |
| `drg_ipsec_connection_id`    | The OCID of the IPSec connection.                    |
| `drg_ipsec_tunnel1_id`       | The OCID of IPSec tunnel 1.                          |
| `drg_ipsec_tunnel2_id`       | The OCID of IPSec tunnel 2.                          |

## Prerequisites

*   **Terraform:** Terraform v1.x or later installed. Verify by running `terraform -v`.
*   **OCI Account:** An active Oracle Cloud Infrastructure (OCI) account.
*   **OCI Permissions:** Your OCI user must have permissions to create the resources defined in this code (VCN, subnets, DRG, compute instances, etc.). You can either be an administrator or have a custom policy that grants these permissions.
*   **OCI API Keys:**
    *   Generate an API signing key pair (private and public keys).
    *   Upload the public key to your OCI user profile.
    *   Note the following, as you'll need it for the `provider.tf` file:
        *   **Tenancy OCID:** Found in the OCI console under **Administration > Tenancy Details**.
        *   **User OCID:** Found in the OCI console under **Identity > Users**. Click on your username.
        *   **Fingerprint:** In your user profile, click on "API Keys" under "Resources" to see the fingerprint.
        *   **Private Key Path:** The path to your private key file on your local machine.
*   **SSH Key Pair:** Generate an SSH key pair for accessing instances. Use `ssh-keygen` (Linux/macOS) or PuTTYgen (Windows).
*   **`provider.tf` File:** Create a file named `provider.tf` in the root directory of your project with the following content:

    ```terraform
    terraform {
      required_providers {
        oci = {
          source  = "oracle/oci"
        }
      }
    }

    provider "oci" {
      tenancy_ocid      = var.tenancy_ocid
      user_ocid         = var.user_ocid
      fingerprint       = var.fingerprint
      private_key_path  = var.private_key_path
      region            = var.region
      compartment_id    = var.compartment_ocid
    }
    ```
    Then add these variables to your main `variables.tf` file:

    ```terraform
    variable "tenancy_ocid" {
      description = "The OCID of your tenancy"
      type = string
    }

    variable "user_ocid" {
      description = "The OCID of your user"
      type = string
    }

    variable "fingerprint" {
      description = "Fingerprint of the API Key"
      type = string
    }

    variable "private_key_path" {
      description = "Path to the private key file"
      type = string
    }

    variable "region" {
      description = "OCI Region"
      type = string
      default = "us-sanjose-1"
    }
    ```
    Populate `terraform.tfvars` with the required variable values:

    ```terraform
    # OCI Provider
    tenancy_ocid     = "ocid1.tenancy.oc1..aaaaaaa...." 
    user_ocid        = "ocid1.user.oc1..aaaaaaaa...."
    fingerprint      = "20:d7:77:55:a7:d6:45:45:55:55:55:55:6a:97:5d:5d"
    private_key_path = "/path/to/your/private_key.pem" # e.g., "~/.oci/oci_api_key.pem"
    region           = "us-sanjose-1"
    ```
## Important Considerations 
* **Image:** Only use EFI machine images to better align with supported configurations.

* **Instance Shape:** Use `VM.Standard.E5.Flex` for better performance.

* **Supported OCPU / RAM:**
    *   **Small (4 OCPUs):** 8 GB RAM
    *   **Medium (16 OCPUs):** 16 GB RAM

## Usage

1. **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Initialize Terraform:**

    ```bash
    terraform init
    ```

3. **Provide Variable Values:**

    *   In your `terraform.tfvars` file, provide values for the following variables:
        *   `compartment_ocid`
        *   `ip_address`
        *   `customer_bgp_asn`
        *   `customer_interface_ip_tunnel1`
        *   `oracle_interface_ip_tunnel1`
        *   `customer_interface_ip_tunnel2`
        *   `oracle_interface_ip_tunnel2`
        *   `ssh_key_file_path`
        *   `object_path`
        *   `hostname`
        *   `password` (**Important:** This variable is marked as sensitive. Terraform will not display its value in CLI output, and it's recommended to use environment variables or a secrets management tool for storing sensitive data.)
        *   `key_filename`
        *   `local_path`
    *   Alternatively, you can set these values using environment variables (`TF_VAR_name`).

4. **Plan the deployment:**

    ```bash
    terraform plan
    ```

5. **Apply the configuration:**

    ```bash
    terraform apply
    ```

6. **Destroy the infrastructure (when no longer needed):**
   
   **Important:** Terraform cannot automatically delete a non-empty Object Storage bucket. You need to manually delete the objects within the bucket before running `terraform destroy`.
   
   **Steps to destroy the infrastructure:**
   
   *  **Delete objects in the bucket:**
      1. Go to the OCI console.
      2. Navigate to **Storage > Buckets**.
      3. Find the bucket created by this module (default name: `OCI-C8KV-BUCKET`).
      4. Click on the bucket name.
      5. Select all objects in the bucket and click **Delete**.
      6. Confirm the deletion.
   *  **Run `terraform destroy`:**
      
      ```bash
      terraform destroy
      ```
      This command will destroy all resources.
