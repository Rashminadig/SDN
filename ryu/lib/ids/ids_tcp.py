from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class IDStcp(object):
    
    def __init__(self,packet_data):
        self.packet_data = packet_data        
    

    def check_packet(self,mode,src,dst): 
        pkt = packet.Packet(self.packet_data.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        
        p_dst = eth_pkt.dst
        p_src = eth_pkt.src
        if (src == 'any' or p_src == src):
            if (dst == 'any' or p_dst == dst):
                if mode == 'alert':
                    print 'Ethernet Attack Packet'    
