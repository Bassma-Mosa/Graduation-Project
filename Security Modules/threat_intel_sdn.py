from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import requests

THREAT_INTELLIGENCE_URL = "https://api.abuseipdb.com/api/v2/check"
API_KEY = "2d92669432958dc2d71c5194caaa1cbdb9a5590d04e2a668717b5a5a9c77bace92d212892681372c"

class ThreatIntelSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ThreatIntelSDN, self).__init__(*args, **kwargs)
        self.blacklist = {}

    def fetch_threat_intelligence(self, ip):
        if ip in self.blacklist:
            return self.blacklist[ip]
        headers = {'Key': API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        response = requests.get(THREAT_INTELLIGENCE_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            score = data['data']['abuseConfidenceScore']
            is_malicious = score > 50
            self.blacklist[ip] = is_malicious
            return is_malicious
        return False

    def block_ip(self, datapath, ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=100, match=match, instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info(f"Blocked malicious IP: {ip}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            if self.fetch_threat_intelligence(src_ip):
                self.block_ip(datapath, src_ip)
