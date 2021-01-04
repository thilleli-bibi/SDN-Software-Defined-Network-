

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
log = core.getLogger()



class Firewall (object):


  def __init__ (self, connection):
   

    def setupProtocolFlow (self, nw_proto, dl_type):
        """
        generic flow-installing function used for ICMP and ARP packet flows
        """
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.nw_src = None
        match.nw_dst = None
        match.tp_src = None
        match.tp_dst = None
        match.nw_proto = nw_proto 
        match.dl_type = dl_type 
        msg.match = match
        msg.hard_timeout = 0
        msg.soft_timeout = 0
        msg.priority = 32768
        action = of.ofp_action_output(port = of.OFPP_NORMAL)
        msg.actions.append(action)
       
        self.connection.send(msg)


    global config
  
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.mac_to_port = {}

    # establish base rules for ICMP, ARP, and dropping unknown packets
   
    # add rule to allow ALL ICMP packets
    setupProtocolFlow(self, pkt.ipv4.ICMP_PROTOCOL, pkt.ethernet.IP_TYPE)

   
    # add rule to allow ALL ARP packets
    setupProtocolFlow(self, pkt.arp.REQUEST, pkt.ethernet.ARP_TYPE)
    setupProtocolFlow(self, pkt.arp.REPLY, pkt.ethernet.ARP_TYPE)
    setupProtocolFlow(self, pkt.arp.REV_REQUEST, pkt.ethernet.ARP_TYPE)
    setupProtocolFlow(self, pkt.arp.REV_REPLY, pkt.ethernet.ARP_TYPE)

    # add rule to drop all packets not defined by another rule
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    msg.match = match
    msg.hard_timeout = 0
    msg.soft_timeout = 0
    msg.priority = 1

   
    self.connection.send(msg)

    priority = 32768 # 0x8000, the default priority
    # Insert flows from config list
    # these rules allow the specified hosts to establish flows that match on the addresses and wildcards
    for rule in config:
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        # Check for malformed IP address and strip subnet rather than host for a more specific
        # rule rather than a more general rule
        rule[srcIP] = clean_ip(rule[srcIP])
        rule[dstIP] = clean_ip(rule[dstIP])
        # need to insert destination IP address into match before the srcIP because
        # of a bug in pox 0.1.0 (betta) that would set the match.nw_src to 0 if set
        # prior to the nw_dst.
        if rule[dstIP] != 'any':
            match.nw_dst = rule[dstIP]
        else:
            match.nw_dst = None
        if rule[srcIP] != 'any':
            match.nw_src = rule[srcIP]
        else:
            match.nw_src = None
        if rule[srcPort] != 'any':
            match.tp_src = int(rule[srcPort]) 
        else:
            match.tp_src = None
        if rule[dstPort] != "any":
            match.tp_dst = int(rule[dstPort]) 
        else:
            match.tp_dst = None
        # specify the IP protocol or lower 8 bits of ARP opcode
        # all packets to match on are TCP
        match.nw_proto = pkt.ipv4.TCP_PROTOCOL 
        # specify all packets as IP
        match.dl_type = pkt.ethernet.IP_TYPE 
        msg.match = match
        msg.hard_timeout = 0
        msg.soft_timeout = 0
        msg.priority = priority
        action = of.ofp_action_output(port = of.OFPP_CONTROLLER)
        msg.actions.append(action)
       
        self.connection.send(msg)


  def resend_packet (self, packet):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
   
    msg = of.ofp_packet_out()
    msg.data = packet

    # Add an action for the switch to handle the packet normally
    out_port = of.OFPP_NORMAL
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def check_config (self, fields):
    """
    check_config() matches packets against incoming rules.  This function is not
    strictly necessary but is useful to verify which rules are being matched.
    """
   
    print fields
    global config, srcIP, srcPort, dstIP, dstPort
    flag = False
    for rule in config:
      if verifyPacketAgainstRule(rule[srcIP], fields[srcIP]):
        if fields[srcPort] == rule[srcPort] or rule[srcPort] == 'any':
          if verifyPacketAgainstRule(rule[dstIP], fields[dstIP]):
            if fields[dstPort] == rule[dstPort] or rule[dstPort] == 'any':
             
              flag = True
              break
    return flag

  def installSymmetricFlow (self, packet, packet_in, allowed):
    """
    installSymmetricFlow() installs flows in both directions for an incoming
    packet that matched a firewall rule
    """
    def installFlow (self, nw_src, nw_dst, tp_src, tp_dst, allowed):
        """
        installFlow() creates a flow for a particular source+port & dest+port
        packet that matched a firewall rule.  It may also create drop rules
        signified by an empty action if the packet is not "allowed"
        """
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.nw_src = nw_src
        match.nw_dst = nw_dst
        match.tp_src = int(tp_src)
        match.tp_dst = int(tp_dst)
        # all packets to match on are TCP
        match.nw_proto = pkt.ipv4.TCP_PROTOCOL # == 6
        # specify all packets as IP
        match.dl_type = pkt.ethernet.IP_TYPE # == 0x0800
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 180 # previously known as soft_timeout
        msg.priority = 49152
        if allowed:
            action = of.ofp_action_output(port = of.OFPP_NORMAL)
            msg.actions.append(action)
        
        self.connection.send(msg)

    # get the IP packet from the payload
    ip_packet = packet.payload

    # get the TCP packet from the IP packet
    tcp_packet = ip_packet.payload
    #fields = [str(ip_packet.srcip), str(tcp_packet.srcport), str(ip_packet.dstip), str(tcp_packet.dstport)]

    # send a message to the switch to install the forward flow
    installFlow(self, ip_packet.srcip, ip_packet.dstip, tcp_packet.srcport, tcp_packet.dstport, allowed)

    # send a message to the switch to install the reverse flow
    installFlow(self, ip_packet.dstip, ip_packet.srcip, tcp_packet.dstport, tcp_packet.srcport, allowed)

    # re-send the first packet of the flow
    Firewall.resend_packet (self, packet)

  def act_like_firewall (self, packet, packet_in):
    
  
    if packet.type == packet.IP_TYPE:
      ip_packet = packet.payload
      if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
        tcp_packet = ip_packet.payload
        fields = [str(ip_packet.srcip), str(tcp_packet.srcport), str(ip_packet.dstip), str(tcp_packet.dstport)]
	# this doesn't necessarily need to check the config since these packets have already been filtered by the switch
    if Firewall.check_config(self, fields):
        allowed = True
    else:
        allowed = False
    # install symmetric flows for the source and destination of the packet
    Firewall.installSymmetricFlow(self, packet, packet_in, allowed)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

   
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message.
    self.act_like_firewall(packet, packet_in)


def parse_config(configuration):
  """
  Read the configuration file into a list of lists
  Assumes the configuration file has rules that are correctly formatted
  as:  <ip> [ / <netmask> ] <port> <ip> [ / <netmask> ] <port>
  """
 
  global config
  fin = open(configuration)
  for line in fin:
    rule = line.split()
    if (len(rule) > 0) : # only make a rule if the line is not empty
        config.append(rule)
  if (False):
    print config


def clean_ip (cidrAddress):
  """
  Takes an address if the address is in CIDR notation and contains uintAddress
  hostAddress then the netmask portion is stripped from the address so that the
  address may be installed as an IP address in uintAddress flow
  (e.g. 192.168.1.4/24 becomes 192.168.1.4)
  """
 
  strAddress = cidrAddress.split('/', 2)
  if len(strAddress) == 1:
	return cidrAddress
  uintAddress = IPAddr(strAddress[0]).toUnsigned()
  hostMask = 32-int(strAddress[1])
  hostAddress = uintAddress & ( (1<<hostMask) - 1 )
  if (hostAddress == 0):
	return cidrAddress
  else:
	return strAddress[0]

def verifyPacketAgainstRule(rule, pkt):
  """
  Takes a rule's address and a packet's address returns true if that address is
  included in that rule.  Assume no rules that contain any for the address will
  not be checked due to logical short-circuiting
  formerly check_rule()
  """

  rule = rule.split('/', 2)
  if rule[0] == 'any':
    if (PRINT_STATUS_INFO):
      print "Match on rule: <",rule,">"
    return True
  if len(rule) == 1:
    return rule[0] == pkt
  else:
    r = IPAddr(rule[0]).toUnsigned()
    p = IPAddr(pkt).toUnsigned()
    m = int(rule[1])
    m = (((1<<m)-1)<<(32-m))
    p = p & m
    return p == r

def launch (configuration=""):
 

  parse_config(configuration) 

  def start_firewall (event):
   
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_firewall)


config = [] 
srcIP = 0
srcPort = 1
dstIP = 2
dstPort = 3

PRINT_STATUS_INFO=True     
PRINT_FUNCTION_NAMES=True  
PRINT_PACKET_CONTENTS=True 
