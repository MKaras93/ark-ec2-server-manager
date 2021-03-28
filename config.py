import os
from dotenv import load_dotenv

load_dotenv("ip_sniffer/.env")

ARK_INSTANCE_ID = "i-0533f1a63bc9afcc7"
ARK_PORT_RANGES = [
    (27015, 27016),
    (7777, 7778)
]
ARK_PORT_PROTOCOL = "UDP"
PERMANENT_IPS_CIDR = [os.getenv("PERMANENT_IP_CIDR")]

KEY_ID = os.getenv("KEY_ID")
ACCESS_KEY = os.getenv("ACCESS_KEY")

ARK_PRIVATE_KEY_LOCATION = os.getenv("ARK_PRIVATE_KEY_LOCATION")

IP_API_URL = os.getenv("IP_API_URL")