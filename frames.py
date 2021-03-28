import ipaddress
import tkinter as tk
from subprocess import Popen
from time import sleep

from ip_sniffer import ip_sniffing, ec2_control
import config


class IpFrame(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        self.grid(
            row=0,
            column=0,
            padx=10,
            pady=20,
        )

        self.label_nvidia_ip = tk.Label(
            master=self,
            text="Nvidia IP"
        )

        self.label_nvidia_ip.grid(
            row=0,
            column=0,
        )

        self.input_nvidia_ip = tk.Entry(
            master=self,
            width=15,
        )

        self.input_nvidia_ip.grid(
            row=0,
            column=1,
        )

        self.button_detect_nvidia_ip = tk.Button(
            master=self,
            command=self._button_detect_nvidia_ip,
            text="Detect",
        )

        self.button_detect_nvidia_ip.grid(
            row=0,
            column=2,
        )

        self.label_local_ip = tk.Label(
            master=self,
            text="Local IP"
        )

        self.label_local_ip.grid(
            row=1,
            column=0,
        )

        self.input_local_ip = tk.Entry(
            master=self,
            width=15,
        )

        self.input_local_ip.grid(
            row=1,
            column=1,
        )

        self.button_detect_local_ip = tk.Button(
            master=self,
            command=self._button_detect_local_ip,
            text="Detect",
        )

        self.button_detect_local_ip.grid(
            row=1,
            column=2,
        )

        self.button_update_security_rules = tk.Button(
            master=self,
            command=self._button_update_security_rules,
            text="Update Rules",
        )

        self.button_update_security_rules.grid(
            row=3,
            column=1,
        )

    def _button_detect_local_ip(self):
        local_ip = ip_sniffing.get_local_ip()
        replace_value_in_widget(self.input_local_ip, local_ip)

    def _button_detect_nvidia_ip(self):
        local_ip = self.input_local_ip.get()
        if not is_valid_ip(local_ip):
            print(f"Given local ip: {local_ip} is not a valid IP address!")
            return
        nvidia_ip = ip_sniffing.get_nvidia_ip(local_ip)
        replace_value_in_widget(self.input_nvidia_ip, nvidia_ip)

    def _button_update_security_rules(self):
        nvidia_ip_range_cidr = f"{self.input_nvidia_ip.get()}/25"
        local_ip_cidr = f"{self.input_local_ip.get()}/32"
        ark_ips = config.PERMANENT_IPS_CIDR + [nvidia_ip_range_cidr]

        ec2_client = ec2_control.get_ec2_client()
        ark_instance = ec2_client.Instance(config.ARK_INSTANCE_ID)

        sec_group = ec2_control.get_security_group(ec2_client, ark_instance)
        ark_rules = []
        for ip_cidr in ark_ips:
            for port_range in config.ARK_PORT_RANGES:
                rule = ec2_control.create_rule(min_port=port_range[0],
                                               max_port=port_range[1],
                                               protocol=config.ARK_PORT_PROTOCOL,
                                               ip_cidr=ip_cidr)
                ark_rules.append(rule)

        ssh_rule = ec2_control.create_rule(
            min_port=22,
            max_port=22,
            protocol="TCP",
            ip_cidr=local_ip_cidr
        )

        security_rules = ark_rules + [ssh_rule]
        ec2_control.clear_sg_rules(sec_group)
        ec2_control.add_sg_rules(sec_group, security_rules)


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def replace_value_in_widget(widget, new_value):
    def _replace_entry(val):
        widget.delete(0, tk.END)
        widget.insert(0, str(val))

    def _replace_label(val):
        widget["text"] = val

    handlers = {
        tk.Entry: _replace_entry,
        tk.Label: _replace_label,
    }

    for key in handlers.keys():
        if isinstance(widget, key):
            handler = handlers.get(key)
            return handler(new_value)


class MachineFrame(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        self.grid(
            row=1,
            column=0,
            # sticky="w",
        )

        self.label_machine_state = tk.Label(
            master=self,
            text="Machine state:"
        )

        self.label_machine_state.grid(
            row=0,
            column=0,
        )

        self.label_machine_state_value = tk.Label(
            master=self,
            width=12,
            bg="#a6a6a6",
        )

        self.label_machine_state_value.grid(
            row=0,
            column=1,
        )

        self.label_machine_ip = tk.Label(
            master=self,
            text="Machine IP:"
        )

        self.label_machine_ip.grid(
            row=1,
            column=0,
        )

        self.entry_machine_ip_value = tk.Entry(
            master=self,
            width=15,
        )

        self.entry_machine_ip_value.grid(
            row=1,
            column=1,
        )

        self.button_machine_start = tk.Button(
            master=self,
            text="Start",
            command=self._button_machine_start,
        )

        self.button_machine_start.grid(
            row=0,
            column=2
        )

        self.button_machine_stop = tk.Button(
            master=self,
            text="Stop",
            command=self._button_machine_stop,
        )

        self.button_machine_stop.grid(
            row=0,
            column=3
        )

        self.button_machine_refresh = tk.Button(
            master=self,
            text="Refresh",
            command=self._button_machine_refresh,
        )

        self.button_machine_refresh.grid(
            row=1,
            column=2
        )

        self.button_ssh = tk.Button(
            master=self,
            text="Open SSH",
            command=self._button_open_ssh,
        )

        self.button_ssh.grid(
            row=3,
            column=1
        )

    def _refresh_machine_state_labels(self, ark_instance):
        """
        Refreshes labels/entries without refreshing the ark instance itself (reuses the ark instance object).
        """
        replace_value_in_widget(self.entry_machine_ip_value, ark_instance.public_ip_address)
        replace_value_in_widget(self.label_machine_state_value, ark_instance.state.get("Name", "unknown"))

    def _button_machine_refresh(self):
        ec2_client = ec2_control.get_ec2_client()
        ark_instance = ec2_client.Instance(config.ARK_INSTANCE_ID)
        ark_instance.reload()
        self._refresh_machine_state_labels(ark_instance)

    def _button_machine_start(self):
        ec2_client = ec2_control.get_ec2_client()
        ark_instance = ec2_client.Instance(config.ARK_INSTANCE_ID)
        ark_instance.start()
        self._refresh_machine_state_labels(ark_instance)
        for i in range(2):
            if self.label_machine_state_value["text"] != "pending":
                return
            sleep(3)
            ark_instance.reload()
            self._refresh_machine_state_labels(ark_instance)

    def _button_machine_stop(self):
        ec2_client = ec2_control.get_ec2_client()
        ark_instance = ec2_client.Instance(config.ARK_INSTANCE_ID)
        ark_instance.stop()
        self._refresh_machine_state_labels(ark_instance)
        for i in range(2):
            if self.label_machine_state_value["text"] != "stopping":
                return
            sleep(3)
            ark_instance.reload()
            self._refresh_machine_state_labels(ark_instance)

    def _button_open_ssh(self):
        command = f"putty ubuntu@{self.entry_machine_ip_value.get()} -i {config.ARK_PRIVATE_KEY_LOCATION}"
        command_args = command.split(" ")
        p = Popen(command_args)