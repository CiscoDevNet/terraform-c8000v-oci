module "vcn" {
  source                            = "./modules/vcn"
  compartment_ocid                  = var.compartment_ocid
  allowed_ports_tcp                 = var.allowed_ports_tcp
  allowed_ports_udp                 = var.allowed_ports_udp
  vcn_name                           = var.vcn_name
  ingress_source_ip                  = var.ingress_source_ip
  subnet_vpn0_cidr_block             = var.subnet_vpn0_cidr_block
  subnet_vpn512_cidr_block           = var.subnet_vpn512_cidr_block
  subnet_vpn0_name                   = var.subnet_vpn0_name
  subnet_vpn512_name                 = var.subnet_vpn512_name
  enable_flag                        = var.enable_flag
  default_route_table_destination_ip = var.default_route_table_destination_ip
  egress_destination_ip             = var.egress_destination_ip
  ig_name                            = var.ig_name
  drg_id = module.drg.drg_id 
  vcn_cidr_block                     = var.vcn_cidr_block
  workload_subnet_cidr_block        = var.workload_subnet_cidr_block 
  workload_subnet_name              = var.workload_display_name
  deployment_mode                   = var.deployment_mode
}

#  module "custom_vm" {
#    source                = "./modules/custom_vm"
#    compartment_ocid      = var.compartment_ocid
#    availability_domain   = var.availability_domain
#    instance_count        = var.instance_count
#    password              = var.password
#    instance_shape        = var.instance_shape
#    region                = var.region
#    ssh_key_file_path     = var.ssh_key_file_path
#    ocpus                 = var.ocpus
#    source_type           = var.source_type
#    vpn0_subnet_id        = module.vcn.subnet_vpn0_id
#    vpn512_subnet_id      = module.vcn.subnet_vpn512_id
#    memory_in_gbs         = var.memory_in_gbs
#    assign_public_ip      = var.assign_public_ip
#    source_id             = module.storage_bucket.custom_image_ocid
#    display_name          = var.display_name
#    local_path            = var.local_path
#    private_key_file_path = var.private_key_file_path
#  }


module "workload_vm" {
  source                        = "./modules/workload_vm"
  compartment_ocid              = var.compartment_ocid
  availability_domain           = var.availability_domain
  workload_display_name = var.workload_display_name
  workload_instance_shape = var.workload_instance_shape
  workload_source_id  = var.workload_source_id
  workload_assign_public_ip     = var.workload_assign_public_ip
  workload_subnet_id        = module.vcn.workload_subnet_id
  workload_source_type = var.workload_source_type
  workload_ocpus    = var.workload_ocpus
  ssh_key_file_path     = var.ssh_key_file_path
  workload_memory_in_gbs     = var.workload_memory_in_gbs 
  region                 = var.region
  workload_vm_shape         = var.workload_vm_shape
   }


module "cpe" {
  source = "./modules/cpe"
  compartment_ocid   = var.compartment_ocid
  cpe_display_name   = var.cpe_display_name
  is_private         = var.is_private
  device_shape_index = var.device_shape_index
}


module "drg" {
  source                         = "./modules/drg"
  compartment_ocid               = var.compartment_ocid
  drg_display_name               = var.drg_display_name
  vcn_id                         = module.vcn.vcn_id
  cpe_id                         = module.cpe.cpe_id
  ipsec_id                       = module.drg.ipsec_id
  drg_route_table_id  = module.vcn.vcn-to-drg-route
  ipsec_display_name             = var.ipsec_display_name
  static_routes                  = var.static_routes
  tunnel1_display_name           = var.tunnel1_display_name
  tunnel2_display_name           = var.tunnel2_display_name
  routing                        = var.routing
  oracle_can_initiate            = var.oracle_can_initiate
  nat_translation_enabled        = var.nat_translation_enabled
  ike_version                    = var.ike_version
  customer_bgp_asn               = var.customer_bgp_asn
  customer_interface_ip_tunnel1  = var.customer_interface_ip_tunnel1
  oracle_interface_ip_tunnel1    = var.oracle_interface_ip_tunnel1
  customer_interface_ip_tunnel2  = var.customer_interface_ip_tunnel2
  oracle_interface_ip_tunnel2    = var.oracle_interface_ip_tunnel2
  phase_one_auth_algorithm       = var.phase_one_auth_algorithm
  phase_one_dh_group             = var.phase_one_dh_group
  phase_one_encryption_algorithm = var.phase_one_encryption_algorithm
  phase_one_lifetime             = var.phase_one_lifetime
  phase_two_encryption_algorithm = var.phase_two_encryption_algorithm
  phase_two_dh_group             = var.phase_two_dh_group
  phase_two_lifetime             = var.phase_two_lifetime
}
