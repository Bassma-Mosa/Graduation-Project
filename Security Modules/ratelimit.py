from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

class RateLimitApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def _init_(self, *args, **kwargs):
        super(RateLimitApp, self)._init_(*args, **kwargs)
        self.rate_limit = 1000  # 1000 packets per second
        self.counters = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # استخراج عنوان IP المصدر
        src_ip = self.extract_ip(msg.data)

        # تحديث العداد
        if src_ip in self.counters:
            self.counters[src_ip] += 1
        else:
            self.counters[src_ip] = 1

        # تطبيق Rate Limiting
        if self.counters[src_ip] > self.rate_limit:
            # إسقاط الحزم إذا تجاوزت الحد
            match = parser.OFPMatch(ipv4_src=src_ip)
            actions = []
            self.add_flow(datapath, 1, match, actions)
        else:
            # إعادة توجيه الحزمة
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=msg.in_port,
                actions=actions,
            )
            datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # إضافة قاعدة Flow
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    def extract_ip(self, data):
        # استخراج عنوان IP من الحزمة
        # (هذا مثال بسيط، قد تحتاج إلى تحليل الحزمة بشكل صحيح)
        return "192.168.1.1"  # مثال لعنوان IP
