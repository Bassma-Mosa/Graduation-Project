from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ip
from ryu.lib.packet import tcp

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, ofproto_v1_3.OFP_VERSION)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # إضافة قاعدة للتحقق من الحزم التي تحتوي على SYN في حقل TCP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x02)  # TCP SYN
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]  # اجراء متاح، مثل الإرسال عبر المنفذ العادي
        self.add_flow(datapath, 10, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # إضافة القاعدة إلى جدول التدفق
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, buffer_id=buffer_id)
        datapath.send_msg(mod)
