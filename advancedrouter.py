from pox.core import core
from netaddr import *
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp, echo
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
import time
import pox

log = core.getLogger()

# Router Configurations
info_table = dict()
info_table[1] = {'Local Networks':'10.0.1.0/24','Gateway':'10.0.1.1', 'MAC':'AA:BB:CC:DD:EE:01', 'Destination Address':'10.0.2.0/24', 'Next Hop':'10.0.2.1'}
info_table[2] = {'Local Networks':'10.0.2.0/24','Gateway':'10.0.2.1', 'MAC':'AA:BB:CC:DD:EE:02', 'Destination Address':'10.0.1.0/24', 'Next Hop':'10.0.1.1'}

#   For each Router object created, it will query for their respective configurations
#   Each router :
#       +   are uniquely identified via their DPID
#       +   has their own CAM, Routing, ARP tables
#   Each different network that exists in a Router will be represented as two different interfaces

#   TODO - 1:   ICMP Destination Unreachable
#   TODO - 2:   Send out buffered frames awaiting for ARP Replies

class Router(object):
    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Switch DPID
        self.dpid = connection.dpid

        # Buffer for packets waiting for ARP
        self.buffer = dict()

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = dict()

        # Router Interfaces
        self.interfaces = dict()
        self.interfaces[info_table[self.dpid]['Gateway']] = {'MAC':info_table[self.dpid]['MAC'], 'Network':info_table[self.dpid]['Local Networks']}
        log.debug("%s %s" % (self.dpid, self.interfaces))

        # ARP Table
        self.arp_table = dict()

        # Routing Table
        self.routing_table = dict()
        self.routing_table[info_table[self.dpid]['Destination Address']] = {'Next Hop' : info_table[self.dpid]['Next Hop'], 'Connected': info_table[self.dpid]['Gateway']}
        log.debug("%s %s" % (self.dpid, self.routing_table))

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in.pack()

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def ARP_Handler(self, etherFrame, packet_in):
        log.debug("%s ARP FRAME RECEIVED FROM %s" % (self.dpid, packet_in.in_port))

        # ARP Request
        if etherFrame.payload.opcode == arp.REQUEST:
            log.debug("IT'S AN ARP REQUEST!")

            arp_payload = etherFrame.payload
            # Is the ARP Request for the Router's Interface/ Gateway?
            arp_request_protodst = str(arp_payload.protodst)
            if arp_request_protodst in self.interfaces:
                # Construct ARP Reply
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = EthAddr(self.interfaces[arp_request_protodst]['MAC'])
                arp_reply.hwdst = arp_payload.hwsrc
                arp_reply.protosrc = arp_payload.protodst
                arp_reply.protodst = arp_payload.protosrc

                ether = ethernet()
                ether.type = ether.ARP_TYPE
                ether.src = EthAddr(self.interfaces[arp_request_protodst]['MAC'])
                ether.dst = arp_payload.hwsrc
                ether.payload = arp_reply
                self.resend_packet(ether, packet_in.in_port)
                log.debug("%s ARP REPLY SENT!" % self.dpid)
            # ARP Request for other hosts in LAN
            else:
                msg = of.ofp_packet_out()
                msg.data = etherFrame
                msg.in_port = packet_in.in_port
                msg.actions.append((of.ofp_action_output(port = of.OFPP_FLOOD)))
                self.connection.send(msg)
                log.debug("%s ARP REQUEST FLOODED TO OTHER PORTS" % self.dpid)

        # ARP Replies
        elif etherFrame.payload.opcode == arp.REPLY:
            log.debug("IT'S AN ARP REPLY!")

            arp_payload = etherFrame.payload
            # Did the Router make the ARP Request?
            arp_reply_protodst = str(arp_payload.protodst)
            if arp_reply_protodst in self.interfaces:
                arp_reply_hwsrc = str(arp_payload.hwsrc)
                arp_reply_protosrc = str(arp_payload.protosrc)

                if arp_reply_protosrc not in self.arp_table:
                    self.arp_table[arp_reply_protosrc] = arp_reply_hwsrc
                    self.mac_to_port[arp_reply_hwsrc] = packet_in.in_port
                    log.debug("%s %s INSTALLED TO CAM TABLE" % (arp_reply_protosrc, arp_reply_hwsrc))
            # Forward the ARP Reply
            else:
                self.resend_packet(etherFrame, self.mac_to_port[str(arp_payload.hwdst)])
                log.debug("ARP Reply from %s to %s forwarded" % (arp_payload.hwsrc, arp_payload.hwdst))
                   

    def ICMP_Handler(self, packet, packet_in):
        ethernet_frame = packet
        ip_packet = packet.payload

        icmp_request_packet = ip_packet.payload

        # ICMP Echo Request (8) -> ICMP Echo Reply (0)
        if icmp_request_packet.type == 8:
            icmp_echo_reply_packet = icmp()
            icmp_echo_reply_packet.code = 0
            icmp_echo_reply_packet.type = 0
            icmp_echo_reply_packet.payload = icmp_request_packet.payload

            ip = ipv4()
            ip.srcip = ip_packet.dstip
            ip.dstip = ip_packet.srcip
            ip.protocol = ipv4.ICMP_PROTOCOL
            ip.payload = icmp_echo_reply_packet

            ether = ethernet()
            ether.type = ethernet.IP_TYPE
            ether.src = ethernet_frame.dst
            ether.dst = ethernet_frame.src
            ether.payload = ip

            self.resend_packet(ether, packet_in.in_port)
            log.debug("%s ICMP ECHO REPLY SENT!" % self.dpid)

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        etherFrame = event.parsed   
        packet_in = event.ofp       

        # Incomplete frames
        if not etherFrame.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # LLDP
        if etherFrame.type == ethernet.LLDP_TYPE:
            log.warning("Ignoring LLDP")
            return

        # ajouter la nouvelle adresse MAC à la table mac
        if str(etherFrame.src) not in self.mac_to_port:
            self.mac_to_port[str(etherFrame.src)] = packet_in.in_port
            log.debug('%s Adding %s into CAM' % (self.dpid, str(etherFrame.src)))

        # Switchable?
        if str(etherFrame.dst) in self.mac_to_port:
            self.resend_packet(etherFrame, self.mac_to_port[str(etherFrame.dst)])
            log.debug("%s Frame can be switched!" % self.dpid)

        else:
            # ARP
            if etherFrame.type == ethernet.ARP_TYPE:
                log.debug('RECEIVED: EtherType -> ARP')
                self.ARP_Handler(etherFrame, packet_in)

            # IP
            elif etherFrame.type == ethernet.IP_TYPE:
                log.debug('%s RECEIVED: EtherType -> IP' % self.dpid)

                # Extract IP Packet from Ethernet Frame
                ip_packet = etherFrame.payload
                destination_ip = str(ip_packet.dstip)

                # For Router?
                if destination_ip in self.interfaces:
                    log.debug('%s ICMP ECHO -> ROUTER INTERFACE' % self.dpid)
                    self.ICMP_Handler(etherFrame, packet_in)
                else:
                    routable = False
                    for netaddr in self.routing_table.keys():
                        destination_network = netaddr
                        if IPAddress(destination_ip) in IPNetwork(destination_network):
                            routable = True
                            log.debug('%s Packet can be routed!' % self.dpid)
                            break

                    local = False
                    if not routable:
                        for netaddr in self.interfaces.keys():
                            destination_network = self.interfaces[netaddr]['Network']
                            if IPAddress(destination_ip) in IPNetwork(destination_network):
                                local = True
                                log.debug('%s Packet forwarded locally!' % self.dpid)
                                break

                    if local:
                        if destination_ip not in self.arp_table:
                            # ARP pour le prochain saut
                            arp_request = arp()
                            arp_request.opcode = arp.REQUEST
                            arp_request.protosrc = IPAddr(netaddr)
                            arp_request.protodst = IPAddr(destination_ip)
                            arp_request.hwsrc = EthAddr(self.interfaces[netaddr]['MAC'])
                            arp_request.hwdst = EthAddr('00:00:00:00:00:00')

                            ether = ethernet()
                            ether.type = ethernet.ARP_TYPE
                            ether.src = EthAddr(self.interfaces[netaddr]['MAC'])
                            ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                            ether.payload = arp_request

                            msg = of.ofp_packet_out()
                            msg.data = ether
                            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                            self.connection.send(msg)
                        if destination_ip in self.arp_table:
                            etherFrame.src = etherFrame.dst
                            etherFrame.dst = EthAddr(self.arp_table[destination_ip])
                            self.resend_packet(etherFrame, self.mac_to_port[self.arp_table[destination_ip]])

                    elif routable:
                        next_hop = self.routing_table[destination_network]['Next Hop']
                        if next_hop not in self.arp_table:
                            # ARP for the Next Hop
                            arp_request = arp()
                            arp_request.opcode = arp.REQUEST
                            arp_request.protosrc = IPAddr(self.routing_table[destination_network]['Connected'])
                            arp_request.protodst = IPAddr(next_hop)
                            arp_request.hwsrc = EthAddr(self.interfaces[self.routing_table[destination_network]['Connected']]['MAC'])
                            arp_request.hwdst = EthAddr('00:00:00:00:00:00')

                            ether = ethernet()
                            ether.type = ethernet.ARP_TYPE
                            ether.src = EthAddr(self.interfaces[self.routing_table[destination_network]['Connected']]['MAC'])
                            ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                            ether.payload = arp_request

                            msg = of.ofp_packet_out()
                            msg.data = ether
                            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                            self.connection.send(msg)
                        if next_hop in self.arp_table:
                            etherFrame.src = EthAddr(self.interfaces[self.routing_table[destination_network]['Connected']]['MAC'])
                            etherFrame.dst = EthAddr(self.arp_table[next_hop])
                            self.resend_packet(etherFrame, self.mac_to_port[self.arp_table[next_hop]])
                            log.debug('%s Packet forwarded to next hop!' % self.dpid)
                   


def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
