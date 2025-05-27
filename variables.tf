#-----------------------------------------------------------------------------
# OCI Authentication Variables
#-----------------------------------------------------------------------------

variable "user_ocid" {
  description = "The OCID of the user making the request"
  type        = string
}

variable "tenancy_ocid" {
  description = "The OCID of the tenancy"
  type        = string
}

variable "fingerprint" {
  description = "The fingerprint of the API key"
  type        = string
}

#-----------------------------------------------------------------------------
# Compartment Configuration
#-----------------------------------------------------------------------------

variable "compartment_ocid" {
  description = "The OCID of the compartment where resources will be created."
  type        = string
}

#-----------------------------------------------------------------------------
# VCN Configuration
#-----------------------------------------------------------------------------

variable "vcn_cidr_block" {
  description = "The CIDR block for the Virtual Cloud Network (VCN)."
  type        = string
  default     = "10.200.0.0/16"
}

variable "vcn_name" {
  description = "The name of the Virtual Cloud Network (VCN)."
  type        = string
  default     = "OCI-SDWAN-VCN"
}

#-----------------------------------------------------------------------------
# Subnet Configuration
#-----------------------------------------------------------------------------

variable "subnet_vpn0_cidr_block" {
  description = "The CIDR block for the VPN0 subnet."
  type        = string
  default     = "10.200.1.0/24"
}

variable "subnet_vpn0_name" {
  description = "The name for the VPN0 subnet."
  type        = string
  default     = "C8KV-VPN0"
}

variable "subnet_vpn512_cidr_block" {
  description = "The CIDR block for the VPN512 subnet."
  type        = string
  default     = "10.200.0.0/24"
}

variable "subnet_vpn512_name" {
  description = "The name for the VPN512 subnet."
  type        = string
  default     = "C8KV-VPN512"
}

#-----------------------------------------------------------------------------
# Internet Gateway Configuration
#-----------------------------------------------------------------------------

variable "ig_name" {
  description = "The name for the Internet Gateway."
  type        = string
  default     = "OCI-SDWAN-IG"
}

#-----------------------------------------------------------------------------
# General Network Configuration
#-----------------------------------------------------------------------------

variable "enable_flag" {
  description = "A flag to enable or disable the creation of resources. Useful for conditional resource creation."
  type        = bool
  default     = true
}

variable "default_route_table_destination_ip" {
  description = "The destination IP for the default route in the route table (typically 0.0.0.0/0 for all traffic)."
  type        = string

}

#-----------------------------------------------------------------------------
# Security List Configuration (Firewall Rules)
#-----------------------------------------------------------------------------

variable "ingress_source_ip" {
  description = "The source IP for ingress firewall rules in the security list"
  type        = string
}

variable "egress_destination_ip" {
  description = "The destination IP for egress firewall rules in the security list (currently allows all - 0.0.0.0/0)."
  type        = string

}

variable "allowed_ports_tcp" {
  description = "A list of TCP ports to allow for ingress traffic in the security list."
  type        = list(number)
  default     = [22, 80, 443, 12346, 12366, 12386, 12406, 12426]
}

variable "allowed_ports_udp" {
  description = "A list of UDP ports to allow for ingress traffic in the security list."
  type        = list(number)
  default     = [500, 4500]
}

#-----------------------------------------------------------------------------
# Object Storage Configuration
#-----------------------------------------------------------------------------

variable "bucket_name" {
  description = "The name of the Object Storage bucket."
  type        = string
  default     = "OCI-C8KV-BUCKET"
}

variable "storage_tier" {
  description = "The storage tier for the bucket (e.g., 'Standard' or 'Archive')."
  type        = string
  default     = "Standard"
}

variable "object_name" {
  description = "The name of the object (file) to be stored in the bucket. This will also be used in the custom image name."
  type        = string
  default     = "Qcow-Image"
}
variable "namespace" {
  description = "The Object Storage namespace for the bucket."
  type        = string
  # You might not want a default here, as it should ideally come from the data source
}

variable "object_path" {
  description = "The local file path of the object (file) to be uploaded to the bucket."
  type        = string
  # No default here as this will be highly specific to the user's local environment.
}


#-----------------------------------------------------------------------------
# Custom VM Configuration
#-----------------------------------------------------------------------------

variable "availability_domain" {
  description = "The availability domain where the instance will be launched."
  type        = string
  default     = "BFeX:US-SANJOSE-1-AD-1"
}

variable "instance_shape" {
  description = "The shape of the instance (e.g., VM.Standard2.1)."
  type        = string
  default     = "VM.Standard.E5.Flex"
  validation {
    condition     = var.instance_shape == "VM.Standard.E5.Flex"
    error_message = "Only VM.Standard.E5.Flex instance shape is supported for C8kv."
  }
}

variable "source_type" {
  description = "The type of source to use for the instance, typically 'image'."
  type        = string
  default     = "image"
}

variable "display_name" {
  description = "The display name for the instance."
  type        = string
  default     = "C8Kv2-Instance"
}

variable "ocpus" {
  description = "The number of OCPUs to allocate to the instance (used with flexible shapes)."
  type        = number
  default     = 4
  validation {
    condition     = contains([4, 16], var.ocpus)
    error_message = "Supported OCPU configurations for C8kv on VM.Standard.E5.Flex are 4 (Small) and 16 (Medium). Please choose a valid OCPU value."
  }
}

variable "memory_in_gbs" {
  description = "The amount of memory (in GB) to allocate to the instance (used with flexible shapes) depending on the OCPUs."
  type        = number
  default     = 8
  validation {
    condition = (
      (var.ocpus == 4 && var.memory_in_gbs == 8) ||
      (var.ocpus == 16 && var.memory_in_gbs == 16)
    )
    error_message = "Invalid memory configuration for C8kv on VM.Standard.E5.Flex. For 4 OCPUs (Small), use 8GB RAM. For 16 OCPUs (Medium), use 16GB RAM."
  }
}

variable "assign_public_ip" {
  description = "Whether to assign a public IP to the instance's primary VNIC."
  type        = bool
  default     = true
}

variable "region" {
  description = "The OCI region."
  type        = string
  default     = "us-sanjose-1"
}

variable "instance_count" {
  description = "The number of instances to create."
  type        = number
  default     = 1
}

variable "ssh_key_file_path" {
  description = "The path to the SSH public key file that will be added to the instance for authorized access."
  type        = string
}


variable "private_key_file_path" {
  description = "Path to the SSH private key file"
  type        = string
}

variable "password" {
  description = "The password for authentication."
  sensitive   = true
}

variable "local_path" {
  description = "The local path to save data."
}


#-----------------------------------------------------------------------------
# CPE Configuration
#-----------------------------------------------------------------------------

variable "cpe_display_name" {
  description = "The display name for the Customer-Premises Equipment (CPE)."
  type        = string
  default     = "C8KV-CPE"
}

variable "ip_address" {
  description = "The public IP address of the Customer-Premises Equipment (CPE)."
  type        = string
  # No default here as this will be specific to the user's CPE.
}

variable "is_private" {
  description = "A boolean indicating whether the CPE uses a private IP address (true) or a public IP address (false)."
  type        = bool
  default     = false
}

variable "device_shape_index" {
  description = "The index of the CPE device shape to use from the list of available shapes. Refer to the output 'oci_core_cpe_device_shapes_list' to see available options."
  type        = number
  default     = 8
}


#-----------------------------------------------------------------------------
# DRG Configuration
#-----------------------------------------------------------------------------

variable "drg_display_name" {
  description = "Display name for the DRG."
  type        = string
  default     = "C8KV-DRG"
}

#-----------------------------------------------------------------------------
# VCN and IPSec Configuration
#-----------------------------------------------------------------------------

variable "static_routes" {
  description = "Static routes for IPSec connection."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ipsec_display_name" {
  description = "Display name for IPSec connection."
  type        = string
  default     = "C8KV-IPSec"
}

#-----------------------------------------------------------------------------
# IPSec Tunnel Management Configuration
#-----------------------------------------------------------------------------

variable "routing" {
  description = "Routing type for the IPSec tunnels (e.g., BGP, STATIC)."
  type        = string
  default     = "BGP"
}

variable "oracle_can_initiate" {
  description = "Whether Oracle can initiate the connection (INITIATOR_OR_RESPONDER)."
  type        = string
  default     = "INITIATOR_OR_RESPONDER"
}

variable "nat_translation_enabled" {
  description = "Whether NAT translation is enabled for the IPSec tunnels."
  type        = string
  default     = "ENABLED"
}

variable "customer_bgp_asn" {
  description = "Customer BGP Autonomous System Number (ASN)."
  type        = string
  # No default as this will be customer-specific
}

variable "customer_interface_ip_tunnel1" {
  description = "Customer interface IP for Tunnel 1 (must be a /30 or /31)."
  type        = string
  # No default as this will be customer-specific
}

variable "oracle_interface_ip_tunnel1" {
  description = "Oracle interface IP for Tunnel 1 (must be a /30 or /31)."
  type        = string
  # No default as this will be customer-specific
}

variable "customer_interface_ip_tunnel2" {
  description = "Customer interface IP for Tunnel 2 (must be a /30 or /31)."
  type        = string
  # No default as this will be customer-specific
}

variable "oracle_interface_ip_tunnel2" {
  description = "Oracle interface IP for Tunnel 2 (must be a /30 or /31)."
  type        = string
  # No default as this will be customer-specific
}

variable "tunnel1_display_name" {
  description = "Display name for Tunnel 1."
  type        = string
  default     = "Tunnel1-to-DRG"
}

variable "tunnel2_display_name" {
  description = "Display name for Tunnel 2."
  type        = string
  default     = "Tunnel2-to-DRG"
}

#-----------------------------------------------------------------------------
# IPSec Phase 1 and Phase 2 Configuration
#-----------------------------------------------------------------------------

variable "phase_one_auth_algorithm" {
  description = "Phase 1 authentication algorithm (e.g., SHA2_256)."
  type        = string
  default     = "SHA2_256"
}

variable "phase_one_dh_group" {
  description = "Phase 1 Diffie-Hellman group (e.g., GROUP14)."
  type        = string
  default     = "GROUP14"
}

variable "phase_one_encryption_algorithm" {
  description = "Phase 1 encryption algorithm (e.g., AES_256_CBC)."
  type        = string
  default     = "AES_256_CBC"
}

variable "phase_one_lifetime" {
  description = "Phase 1 lifetime in seconds (e.g., 28800)."
  type        = number
  default     = 28800
}

variable "phase_two_encryption_algorithm" {
  description = "Phase 2 encryption algorithm (e.g., AES_256_GCM)."
  type        = string
  default     = "AES_256_GCM"
}

variable "phase_two_dh_group" {
  description = "Phase 2 Diffie-Hellman group (e.g., GROUP20)."
  type        = string
  default     = "GROUP20"
}

variable "phase_two_lifetime" {
  description = "Phase 2 lifetime in seconds (e.g., 3600)."
  type        = number
  default     = 3600
}

variable "ike_version" {
  description = "IKE version for the IPSec tunnels (e.g., V2)."
  type        = string
  default     = "V2"
}


variable "workload_subnet_cidr_block" {
  description = "CIDR block for workload subnet"
  type        = string
}


variable "workload_display_name" {
  description = "Workload Name to be provisioned"
  type        = string
  default     = "Workload_VM"

}

variable "workload_instance_shape" {
  description = "workload VM instance"
  type        = string
  default     = "VM.Standard.E2.1.Micro"

}

variable "workload_source_id" {
  description = "The OCID of the custom image to use for the instance."
  type        = string
}

variable "workload_assign_public_ip" {
  description = "Whether to assign a public IP to the workload. Should be false"
  type        = bool
}

# variable "workload_subnet_id" {
#   description = "The OCID of the Workload subnet id to be allocated"
#   type        = string
# }

variable "workload_memory_in_gbs" {
  description = "Amount of memory to allocate to the workload"
  type        = number
  default     = 6
}

variable "workload_ocpus" {
  description = "Number of OCPU to allocate for the workload"
  type        = number
  default     = 1
}

variable "workload_source_type" {
  description = "The type of source to use for the instance, typically 'image'."
  type        = string
  default     = "image"
}
variable "deployment_mode" {
  description = "The deployment mode for C8kv. Valid values are 'Autonomous' or 'Controller'."
  type        = string
  default     = "Autonomous"
  validation {
    condition     = contains(["Autonomous", "Controller"], var.deployment_mode)
    error_message = "Valid values for deployment_mode are 'Autonomous' or 'Controller'."
  }
}

variable "workload_vm_shape" {
  description = "Workload VM Shape type to be provisioned"
  type        = string
  default = "VM.Standard.E4.Flex"
}