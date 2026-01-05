import ryu.ofproto.ofproto_v1_3_parser
import ipaddress
import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import in_proto
from net_config import NET_CONFIG
from net_config import SERVICE_PORT
from net_config import match_patterns

logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S")

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)


        self.HPOT_READY = False
        self.SERVER_READY = False
        self.SWITCH_VIRTUAL_MAC = NET_CONFIG["virtual_mac"]

        self.networks = []      # Network's detail dictionary
        self.gateways = []      # Subnets gateway IP addresses
        self.trusted_ips = {}   # IP -> LoT association
        self.ip_to_mac = {}     # IP -> MAC association

        # Parse NET_CONFIG
        logging.info("Importing network configuration")
        for item in NET_CONFIG["subnets"]:

            self.networks.append({"network": ipaddress.ip_network(item["network"]), 
                                    "port": item["port"], 
                                    "gateway": item["gw"], 
                                    "trusted": item["trusted"], 
                                    "hpot": item["hpot"]})
            self.gateways.append(item['gw'])

            # Find honeypot subnet
            if item["hpot"]:
                self.HPOT_SUBNET = ipaddress.ip_network(item["network"])
                self.HPOT_PORT = item["port"]

            # Find server subnet
            elif item["server"]:
                self.SERVER_SUBNET = ipaddress.ip_network(item["network"])
                self.SERVER_PORT = item["port"]

        logging.info("Network configuration imported")

    # Add a new flow table record
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        logging.info("Sending a FLOW_MOD to switch")
        datapath.send_msg(mod)

    def checkTrustworthiness(self, ip):
        ip_addr = ipaddress.ip_address(ip)

        # Search in networks
        for item in self.networks:
            if ip_addr in item["network"] and item["trusted"]:
                self.trusted_ips[ip] = True
                logging.info("%s trustworthiness evaluated: TRUSTED", ip)
                return
        self.trusted_ips[ip] = False
        logging.warning("%s trustworthiness evaluated: UNTRUSTED", ip)

    def isTrusted(self, ip):
        if ip not in self.trusted_ips:
            self.checkTrustworthiness(ip)
        return self.trusted_ips[ip]


    # On controller-switch handshake
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Signal VMs to initializes network
        with open("shared/controller.ready", "w") as f:
            pass 

    # On packet-in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            logging.warning("Packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']
        install_flow = True
        on_routing = False
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        self.ip_to_mac.setdefault(dpid, {})

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # |================|
        # | ARP MANAGEMENT |
        # |================|  
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)

            logging.info("ARP | from %s - %s (port %s)", arp_pkt.src_ip, arp_pkt.src_mac[-5:], in_port)

            # Self-Learning IP - MAC association
            self.ip_to_mac[dpid][arp_pkt.src_ip] = arp_pkt.src_mac

            # Find HoneyPot IP address
            if not self.HPOT_READY and ipaddress.ip_address(arp_pkt.src_ip) in self.HPOT_SUBNET:
                self.HPOT_IP = arp_pkt.src_ip
                self.HPOT_READY = True
                logging.info("HoneyPot Up: %s (port %s)", self.HPOT_IP, in_port)

            # Find Server IP address
            if not self.SERVER_READY and ipaddress.ip_address(arp_pkt.src_ip) in self.SERVER_SUBNET:
                self.SERVER_IP = arp_pkt.src_ip
                self.SERVER_READY = True
                logging.info("Server Up: %s (port %s)", self.SERVER_IP, in_port)

            # Check Trustworthiness
            if arp_pkt.src_ip not in self.trusted_ips:
                self.checkTrustworthiness(arp_pkt.src_ip)

            # Manage ARP Request for gateway
            if arp_pkt.opcode == arp.ARP_REQUEST:
                if arp_pkt.dst_ip in self.gateways:
                    logging.info("===> ARP-Request | Received 'who has %s?'", arp_pkt.dst_ip)

                    # Create ARP reply
                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(ethernet.ethernet(ethertype = eth.ethertype, dst = eth.src, src = self.SWITCH_VIRTUAL_MAC))
                    arp_reply.add_protocol(arp.arp(opcode = arp.ARP_REPLY, 
                                                    src_mac = self.SWITCH_VIRTUAL_MAC, 
                                                    src_ip = arp_pkt.dst_ip, 
                                                    dst_mac = arp_pkt.src_mac, 
                                                    dst_ip = arp_pkt.src_ip))

                    arp_reply.serialize()

                    # Send ARP reply
                    actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(datapath = datapath, 
                                                buffer_id = ofproto.OFP_NO_BUFFER, 
                                                in_port=ofproto.OFPP_CONTROLLER, 
                                                actions = actions, 
                                                data = arp_reply.data)
                    datapath.send_msg(out)
                    logging.info("===> ARP-Reply | Sending 'Gate %s at %s!' to %s|%s (out-port: %s)", arp_pkt.dst_ip, self.SWITCH_VIRTUAL_MAC[-5:], arp_pkt.src_ip, arp_pkt.src_mac[-5:], in_port)
                    return

                else:
                    logging.error("===> Unknown gateway")
                    return


        # |=================|
        # | IPv4 MANAGEMENT |
        # |=================| 
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)

            logging.info("IPv4 | %s -> %s (port %s)", ip_pkt.src, ip_pkt.dst, in_port)

            # Drop discovery IPv4 packets
            if ip_pkt.dst in self.gateways:
                logging.warning("===> Switch is final destination: DROPPED")
                
                # Drop discovery packet
                match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ipv4_dst = ip_pkt.src, ipv4_src = ip_pkt.src)
                actions = []

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                else:
                    self.add_flow(datapath, 1, match, actions)
                return

            # Trust level
            trust_level = self.isTrusted(ip_pkt.src)

            # Determine target subnet
            target_ip = ipaddress.ip_address(ip_pkt.dst)
            target_subnet = None

            for item in self.networks:
                if target_ip in item["network"]:
                    target_subnet = item                    
                    break
            
            if target_subnet:
                out_port = target_subnet["port"]
                dst = ip_pkt.dst
                logging.info("===> %s reachable via port %s", target_subnet["network"], target_subnet["port"])
            else:
                logging.error("===> %s is unknown", ip_pkt.dst)
                return


            if ip_pkt.dst == self.SERVER_IP and not trust_level:

                # |============|
                # | DPI MODULE |
                # |============|
                install_flow = False
                if ip_pkt.proto == in_proto.IPPROTO_TCP:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)

                    # Check for right port and payload
                    if tcp_pkt.dst_port == SERVICE_PORT and isinstance(pkt.protocols[-1], (bytes, bytearray)):
                        logging.info("===> TCP | Inspecting TCP packet from un-trusted IP to %s:%s", self.SERVER_IP, tcp_pkt.dst_port)

                        try:
                            # Decode higher level payload
                            payload = pkt.protocols[-1].decode("utf-8", errors="ignore")

                            pattern = match_patterns(payload)
                            if pattern:
                                logging.warning("===> INTRUSION: un-trusted device asking for %s", pattern)

                                if self.HPOT_READY:
                                    dst = self.HPOT_IP
                                    out_port = self.HPOT_PORT
                                    install_flow = True
                                    on_routing = True

                                    # Add reverse NAT flow
                                    match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ipv4_dst = ip_pkt.src, ipv4_src = self.HPOT_IP)
                                    actions = [
                                        parser.OFPActionSetField(eth_src = self.SWITCH_VIRTUAL_MAC),
                                        parser.OFPActionSetField(eth_dst = eth.src),
                                        parser.OFPActionSetField(ipv4_src = self.SERVER_IP),
                                        parser.OFPActionDecNwTtl(),
                                        parser.OFPActionOutput(in_port)]

                                    logging.info("===> Add Reverse-NAT flow to reach %s (port %s)", eth.src[-5:], in_port)
                                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                                        return
                                    else:
                                        self.add_flow(datapath, 1, match, actions)
                                    
                                    # Drop RST
                                    logging.info("===> Drop RST Message")
                                    match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, 
                                                            ipv4_dst = ip_pkt.src, 
                                                            ipv4_src = ip.pkt.dst,
                                                            ip_proto = in_proto.IPPROTO_TCP,
                                                            tcp_flags = 0x04)
                                    actions = []
                                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                                        return
                                    else:
                                        self.add_flow(datapath, 1, match, actions)

                                else:
                                    logging.error("===> Honeypot is unreachable")
                                    return
                        except:
                                pass
            
            # Determine target MAC address
            dst_mac = self.ip_to_mac[dpid].get(dst)

            if dst_mac:

                # === FORWARD PACKET ===
                logging.info("===> MAC address for %s already known: %s", dst, dst_mac)
                
                actions = [
                    parser.OFPActionSetField(eth_src = self.SWITCH_VIRTUAL_MAC),
                    parser.OFPActionSetField(eth_dst = dst_mac)]

                # Change packet destination IP
                if on_routing:
                    logging.warning("===> Re-routing packets to %s:%s", dst, dst_mac[-5:])
                    actions.append(parser.OFPActionSetField(ipv4_dst = dst))

                actions.append(parser.OFPActionDecNwTtl())
                actions.append(parser.OFPActionOutput(out_port))

                # Add flow
                if install_flow:
                    match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ipv4_dst = ip_pkt.dst, ipv4_src = ip_pkt.src)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)

                # Send current packet
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath = datapath, buffer_id = msg.buffer_id, in_port = in_port, actions = actions, data = data)
                datapath.send_msg(out)
                return

            else:

                # === SEND ARP REQUEST ===
                logging.info("===> MAC address for %s unknown, sending ARP request", ip_pkt.dst)
                
                arp_req = packet.Packet()
                arp_req.add_protocol(ethernet.ethernet(ethertype = ether_types.ETH_TYPE_ARP, dst = "ff:ff:ff:ff:ff:ff", src = self.SWITCH_VIRTUAL_MAC))
                arp_req.add_protocol(arp.arp(opcode = arp.ARP_REQUEST, 
                                                src_mac = self.SWITCH_VIRTUAL_MAC, 
                                                src_ip = target_subnet["gateway"], 
                                                dst_mac = "00:00:00:00:00:00", 
                                                dst_ip = ip_pkt.dst))

                arp_req.serialize()

                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath = datapath, 
                                            buffer_id = ofproto.OFP_NO_BUFFER, 
                                            in_port = ofproto.OFPP_CONTROLLER, 
                                            actions = actions, 
                                            data = arp_req.data)

                datapath.send_msg(out)
                logging.info("===> Broadcasting 'who has %s'! out-port: %s", ip_pkt.dst, out_port)
                return