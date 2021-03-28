from config import ARK_INSTANCE_ID, ARK_PORT_RANGES, ARK_PORT_PROTOCOL, PERMANENT_IPS_CIDR
from .ec2_control import get_ec2_client, get_security_group, create_rule, add_sg_rules, clear_sg_rules
from .ip_sniffing import get_local_ip, get_nvidia_ip

local_ip = get_local_ip()
print(f"Local ip: {local_ip}")
if local_ip is None:
    print("Can't obtain local ip. You will have to set up ip for ssh manually.")
else:
    print(f"local ip: {local_ip}")
print("Sniffing Nvidia machine id...")
nvidia_ip = get_nvidia_ip(local_ip)
if nvidia_ip is None:
    print("No connections to Nvidia detected. Aborting.")
    exit()
print(f"Nvidia IP found: {nvidia_ip}")
nvidia_ip_range_cidr = f"{nvidia_ip}/25"

ark_ips = PERMANENT_IPS_CIDR + [nvidia_ip_range_cidr]

ec2_client = get_ec2_client()
ark_instance = ec2_client.Instance(ARK_INSTANCE_ID)

sec_group = get_security_group(ec2_client, ark_instance)

ark_rules = []
for ip_cidr in ark_ips:
    for port_range in ARK_PORT_RANGES:
        rule = create_rule(min_port=port_range[0],
                           max_port=port_range[1],
                           protocol=ARK_PORT_PROTOCOL,
                           ip_cidr=ip_cidr)
        ark_rules.append(rule)

ssh_rule = create_rule(
    min_port=22,
    max_port=22,
    protocol="TCP",
    ip_cidr=f"{local_ip}/32"
)

security_rules = ark_rules + [ssh_rule]
clear_sg_rules(sec_group)
add_sg_rules(sec_group, security_rules)
print("Complete.")

print(f"starting instance: {ARK_INSTANCE_ID}")
# ark_instance.start()
print(f"Instance state: {ark_instance.state}")
# # command = "./start.sh"
# # execute_command(ark_instance_id, command)
# print(f"Instance ready to accept connections at {ark_instance.public_ip_address}")
