import pyshark
import requests
import config

def get_local_ip():
    return requests.get(config.IP_API_URL).json().get("ip")


def get_nvidia_ip(local_ip):
    nvidia_port = 49006
    bp_filter = f"udp port {nvidia_port} and ip src not {local_ip}"
    cap = pyshark.LiveCapture(interface="Ethernet", bpf_filter=bp_filter)
    cap.sniff(1, timeout=10)
    if not len(cap):
        print("Nvidia ip not found. Are you connected to the machine?")
    else:
        return cap.next().ip.addr
