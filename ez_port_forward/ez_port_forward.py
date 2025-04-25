# ez-port-forward makes it easier to create portforwarding rules via DNAT for proxmox systems or similar.
# Copyright (C) 2024  Raphael Kriegl

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


from io import TextIOWrapper
from typing import Optional
import sys
import argparse
from pathlib import Path

import yaml
from yaml import Loader

import ipaddress
import logging

logger = logging.getLogger(__name__)

# this dict keeps track of all ports opened
existing_port_maps: dict[Optional[ipaddress.IPv4Address], tuple[int, str], ipaddress.IPv4Address] = dict()


def parse_tcpudp_protocols(prot_obj):
    # returns dict that maps source ports to dest ports
    if not prot_obj:
        return None
    # bool is an invalid datatype, but would be accepted by the int check later
    if isinstance(prot_obj, bool):
        return None

    # if ports are given as comma separated list, it is read as text.
    # if only list is given, we assume identical source and dest ports
    if isinstance(prot_obj, str):
        return {int(x.strip()): int(x.strip()) for x in prot_obj.split(",")}
    # single ports are parsed as int
    elif isinstance(prot_obj, int):
        return {prot_obj: prot_obj}
    # yaml is read as dict, we only convert keys and values to ints
    elif isinstance(prot_obj, dict):
        out_dict = dict()
        for k, v in prot_obj.items():
            try:
                if v is None:
                    v = k
                elif isinstance(v, bool):
                    if v:  # if true then assume identical in and out ports
                        v = k
                    else:  # if false then invalid
                        raise ValueError()
                if isinstance(v, float) or isinstance(k, float):
                    raise ValueError()
                out_dict[int(k)] = int(v)
            except ValueError:
                logger.error(
                    f"Some port information is invalid: ({k}:{v}  <{type(k).__name__}>:<{type(v).__name__}>). Please check source!"
                )
        return out_dict if out_dict else None
    # if yaml is incorrectly formatted, or entry is missing
    else:
        logger.error(f"Invalid datatype for ports: {type(prot_obj)}")
        return None


def parse_ssh_protocol(ssh_obj, container_id):
    if container_id > 654:
        logger.error(
            f"Container {container_id}: Container ID too large to build vaild SSH Port. Use tcp with custom external port instead."
        )
        return None
    default = {container_id * 100 + 22: 22}

    # assign default if key exists and no int value is specified
    if ssh_obj is None:
        return default

    # check if ssh key in dict, and if it has a specified value
    if isinstance(ssh_obj, str):
        logger.error(
            f"Container {container_id}: SSH only supports single number values."
        )
        return None

    if isinstance(ssh_obj, bool):
        # assign default if key exists and no int value is specified
        if ssh_obj:
            return default
        else:
            return None

    # use specified internal ssh port if given
    if isinstance(ssh_obj, int):
        if ssh_obj >= 100:
            logging.error(
                f"Container {container_id}: SSH port above 100 not supported. Please use TCP instead."
            )
            return None

        return {container_id * 100 + ssh_obj: ssh_obj}

    logger.error(
        f"Container {container_id}: Invalid SSH value type: {ssh_obj} ({type(ssh_obj)})"
    )
    return None


def parse_ip(ip) -> Optional[ipaddress.IPv4Address]:
    if not ip:
        return None

    parsed = ipaddress.ip_address(ip)

    if isinstance(parsed, ipaddress.IPv6Address):
        logger.error("IPv6 destination addresses not yet implemented")
        raise ValueError()

    return parsed


def build_command(
    protocol: str,
    bridge: str,
    from_ip: Optional[ipaddress.IPv4Address],
    from_port: Optional[int],
    to_ip: ipaddress.IPv4Address,
    to_port: int,
    failure: bool
):
    if not from_port:
        from_port = to_port

    command = f"iptables -t nat -A PREROUTING -i {bridge} -p {protocol}"
    if from_ip:
        command += f" -d {from_ip}"
    command += f" --dport {from_port} -j DNAT --to-destination {to_ip}:{to_port}"

    if failure:
        up = f"\t# post-up {command}\n"
        down = f"\t# post-down {command}\n"
    else:
        up = f"\tpost-up {command}\n"
        down = f"\tpost-down {command}\n"

    return up + down + "\n"


def write_container_commands(
    file: TextIOWrapper,
    bridge: str,
    from_ip: Optional[ipaddress.IPv4Address],
    to_ip: ipaddress.IPv4Address,
    ssh_rule=None,
    tcp_rules=None,
    udp_rules=None,
    tcpudp_rules=None,
):
    def write_rules_helper(prot, from_port, to_port):
        logger.debug(f"\tProtocol:{prot}, From:{from_port}, To:{to_port}")

        # if something else is wrong and the port is invalid
        if not (from_port and to_port):
            logger.warning(
                f"Either Port {from_port} or {to_port} is missing or invalid."
            )
            return

        fail = False

        # if port number too large
        if from_port > 65535 or to_port > 65535:
            logger.warning(
                f"Port {from_port} or {to_port} larger than max allowed (65535). Port forward will be commented out in the file."
            )
            fail = True

        # if port was already opened
        if (from_ip, from_port, prot) in existing_port_maps.keys():
            logger.warning(
                f"Port {from_port} already opened for {existing_port_maps[(from_ip, from_port, prot)]}. Port forward will be commented out in the file."
            )
            fail = True
        else:
            existing_port_maps[(from_ip, from_port, prot)] = to_ip

        file.write(build_command(prot, bridge, from_ip, from_port, to_ip, to_port, fail))

    if ssh_rule:
        write_rules_helper("tcp", *list(ssh_rule.items())[0])

    if tcp_rules:
        for src, dest in tcp_rules.items():
            write_rules_helper("tcp", src, dest)

    if udp_rules:
        for src, dest in udp_rules.items():
            write_rules_helper("udp", src, dest)

    if tcpudp_rules:
        for src, dest in tcpudp_rules.items():
            write_rules_helper("tcp", src, dest)
            write_rules_helper("udp", src, dest)


def parse_yaml(yaml_file):
    with open(yaml_file) as conf:
        try:
            yaml_dict: dict = yaml.load(conf, Loader)
        except yaml.YAMLError as ye:
            logger.error(f"Error while parsing YAML file:  {str(ye)}")
            raise

    return yaml_dict


def write_iptables_file(yaml_dict, out_file):
    with open(out_file, "w") as output:
        for iname, iconf in yaml_dict.items():
            output.write("#===========================\n")
            logger.debug(f"Entering interface {iname}")
            output.write(f"iface {iname} inet static\n")
            bridge = iconf.pop("bridge")
            subnet = ipaddress.IPv4Network(iconf.pop("subnet"))
            for cont_id, cont_conf in iconf["forwards"].items():
                output.write(f"\t#--- Container {cont_id}\n")
                logger.debug(f"Parsing rules for container {cont_id}")
                try:
                    from_ip = parse_ip(cont_conf.pop("ip", None))
                    to_ip = subnet[cont_id]
                    ssh = parse_ssh_protocol(cont_conf.pop("ssh", False), cont_id)
                    tcp = parse_tcpudp_protocols(cont_conf.pop("tcp", None))
                    udp = parse_tcpudp_protocols(cont_conf.pop("udp", None))
                    tcpudp = parse_tcpudp_protocols(cont_conf.pop("tcpudp", None))

                    logger.debug(f"Writing rules for container {cont_id}")

                    write_container_commands(
                        output,
                        bridge,
                        from_ip,
                        to_ip,
                        ssh,
                        tcp,
                        udp,
                        tcpudp,
                    )
                except Exception as ex:
                    logger.error(
                        f"Error while parsing rules for Container ID {cont_id} for interface <{iname}> with subnet <{subnet}>: \n{ex}"
                    )
                    output.write("\t# ERROR -- See console log.\n\n")
                    continue

            output.write("#===========================\n")


def main(args=None):
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    logger.addHandler(ch)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input_yaml",
        type=str,
        default="./port_conf.yaml",
        help="The input yaml file. Defaults to ./port_conf.yaml",
        nargs="?",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="/etc/network/interfaces.d/port_forwards",
        help="Target path. Optional, defaults to /etc/network/interfaces.d/port_forwards",
        nargs="?",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    args = parser.parse_args(args)

    yaml_path = Path(args.input_yaml)
    out_path = Path(args.output)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    assert yaml_path.exists(), f"Input file does not exist. {yaml_path}"

    yaml_dict = parse_yaml(yaml_path)

    write_iptables_file(yaml_dict, out_path)


if __name__ == "__main__":
    main()
