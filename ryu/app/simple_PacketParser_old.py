import logging
import struct
import gevent
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.ids import ids_monitor
from array import *

class SimplePacketParser(app_manager.RyuApp):
    _CONTEXTS = {
                 'dpset': dpset.DPSet,
                 'ids_monitor': ids_monitor.IDSMonitor
                 }
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimplePacketParser, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
        self.ids_monitor = kwargs['ids_monitor']

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def delete_flow_entry(self,datapath):
        match = datapath.ofproto_parser.OFPMatch(
              datapath.ofproto.OFPFW_ALL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=datapath.ofproto.OFPFC_DELETE)

        datapath.send_msg(mod)
    

    def packetParser(self, msg):
        my_array = array('B', msg.data)
        pkt = packet.Packet(my_array)
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name') is False:
                print 'data:', p
            else:
                print p.protocol_name
                if p.protocol_name == 'ethernet':
                    print 'ethernet src = ', p.src
                    print 'ethernet dst = ', p.dst
                    print 'ethernet type = ', p.ethertype
                if p.protocol_name == 'arp':
                    print 'arp src mac = ', p.src_mac
                    print 'arp src ip = ', p.src_ip
                    print 'arp dst mac = ', p.dst_mac
                    print 'arp dst ip = ', p.dst_ip
                    
                if p.protocol_name == 'ipv4':
                    print 'ipv4 id = ', p.identification
                    print 'ipv4 src ip = ', p.src
                    print 'ipv4 dst ip = ', p.dst
                    print 'ipv4 flags = ', p.flags
                if p.protocol_name == 'icmp':
                    print 'icmp type = ', p.type
                    print 'icmp code = ', p.code
                    print 'icmp data = ', p.data
                if p.protocol_name == 'tcp':
                    print 'tcp src port = ', p.src_port
                    print 'tcp dst port = ', p.dst_port
                    print 'tcp options = ', p.option
            
                
    @handler.set_ev_cls(dpset.EventDP)
    def dp_handler(self, ev):
        if not ev.enter:
            return

        dp = ev.dp
        self.delete_flow_entry(dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        
            
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
        
        #self.packetParser(msg)
        gevent.spawn_later(0, self.ids_monitor.check_packet(msg))
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                   #datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        # install a flow to avoid packet_in next time
        #if out_port != ofproto.OFPP_FLOOD:
           #self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)


    @set_ev_cls(ids_monitor.AttackAlert)
    def _dump_alert(self, ev):
        alertmsg = ev.alertmsg
        msg = ev.data

        print '---------------alertmsg:', ''.join(alertmsg)
        #print 'Packet causing alert'

        #self.packetParser(msg)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
