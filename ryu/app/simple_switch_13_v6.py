# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.mac import haddr_to_bin
from ryu.controller import dpset
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4      
from ryu.lib.ids import ids_utils    
from ryu.lib import dpid as dpid_lib 
from ryu.lib.ids import ids_monitor
from array import *		   
import MySQLdb as mdb              
import collections



class SimpleSwitch13(app_manager.RyuApp):
    _CONTEXTS = {
                 'dpset': dpset.DPSet,
                 'ids_monitor': ids_monitor.IDSMonitor
                 }                            
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    global src_ip  
    src_ip = '0.0.0.0'
    global dst_ip  
    dst_ip = '1.1.1.0'

    global bad_pkt_limit
    bad_pkt_limit = 5   
    global threshold  
    threshold = 115   

    global packet_threshold  
    packet_threshold = 10
    global allow_host
    allow_host= [True,True,True,True,True,True,True]       	

    global flow_count 
    flow_count = [0,0,0,0,0,0,0,0,0,0,0]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	self.dpset = kwargs['dpset']   
        self.ids_monitor = kwargs['ids_monitor'] 

        global hosts
        hosts={}
        global newhosts
        newhosts={}
        global oldhosts
        oldhosts={}

        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
	print " ~~~~ Inside simple switch 1.3" 

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    def del_flow(self, datapath, match):
         ofproto = datapath.ofproto
         parser = datapath.ofproto_parser
         mod = parser.OFPFlowMod(datapath=datapath,
         command=ofproto.OFPFC_DELETE,
                 out_port=ofproto.OFPP_ANY,
                 out_group=ofproto.OFPG_ANY,
                 match=match)
         datapath.send_msg(mod)    


    def chk_pkt_value(self):         

        global good_pkt 
        good_pkt= True 
        f= open('/home/rashmi/RYU295/ryu/lib/ids/pkt_value.txt', 'r')
        for line in f:
           if "False" in line:
              print " Packet type is : Bad packet "
              good_pkt=False
              break
        return good_pkt 

    def get_host_name(self,src_ip):  
   	global host_name   
	if(src_ip[-2]== '.'):
	     host_name = src_ip[-1]
   	else:
     	    host_name = src_ip[-2:]
        return host_name

    def validate_host(self,src_ip,host_name,bad_pkt_limit):  
        bad_pkt_count =0;
        
        global is_good_host 
        is_good_host = True

        global allow_host 
	
        f= open('/home/rashmi/RYU295/ryu/lib/ids/hosts_log/host%s.txt' % host_name, 'r')
        for line in f:
           if "bad" in line:
              print " Host is : Bad "
              bad_pkt_count += 1


        if(bad_pkt_count > bad_pkt_limit):
	   is_good_host = False
	else:
	   is_good_host = True

        for j in hosts:
            self.logger.info("Host IP= %s,packet count in current interval=%d",j,hosts[j])

        global packet_threshold
        hoststuple = collections.namedtuple('hoststuple', 'packets hostname')

        best = sorted([hoststuple(v,k) for (k,v) in hosts.items()], reverse=True)
        if best:
            hoststuple = best[0]
	
        self.logger.info("Host with max Packets in cur interval is %s The Packet Count is %s",hoststuple.hostname,hoststuple.packets)
	if(hoststuple.packets >= packet_threshold):
	     if(src_ip == hoststuple.hostname):
		  allow_host[int(host_name)] = False  	
	     else:
		  allow_host[int(host_name)] = True	
         
        return ((is_good_host),(allow_host[int(host_name)])) 
    
    def flow_consistency_check(self,datapath,match,actions,out_port,host_name): 

          f= open('/home/rashmi/RYU295/ryu/lib/switch_flows.txt', 'r') 
          d = dict()
          for line in f:
           if line in d:
              print ".... Flow rule already exists .... "
              d[line] += 1
              
              print "checking user input"
              file = open('/home/rashmi/RYU295/ryu/lib/flow_decision.txt', 'r') 
              usr_input = open('/home/rashmi/RYU295/ryu/lib/flow_decision.txt').read()               
              option= str(usr_input)   
              print "The option you entered is: ", option
              
              if "yes" in file: 
                  print " ~~ Replacing the flow .. "   
                  self.add_flow(datapath, 1, match, actions)
                  
              else:
                  print " ~~ Flow ignored .. "  


           else:
              d[line] = 1
              
              self.add_flow(datapath, 1, match, actions) 
              
           

    
    def packetParser(self, msg, packettype,actiontaken):           


        my_array = array('B', msg.data)
        pkt = packet.Packet(my_array)
        
        for p in pkt.protocols:
	    if hasattr(p, 'protocol_name') is True:
                if p.protocol_name == 'ethernet':
                      #print 'ethernet src = ', p.src
                      #print 'ethernet dst = ', p.dst
#                     print 'ethernet type = ', p.ethertype
                      src_mac = p.src
                      dst_mac = p.dst  
                    
                if p.protocol_name == 'ipv4':
#                     print 'ipv4 id = ', p.identification
                      #print 'ipv4 src ip = ', p.src
                      #print 'ipv4 dst ip = ', p.dst
                      #print 'ipv4 flags = ', p.flags
                      global src_ip #--sn
		      global dst_ip #--sn  
                      src_ip = p.src
                      dst_ip = p.dst 
		      #print "In ipv4 src ip: ", src_ip
		      #print "In ipv4 dst ip: ", dst_ip
		      if p.flags is not None: 	
                         ip_flags = 'IP flags = '+ str(p.flags)
                      else:
			 ip_flags = p.flags
                      self.writeToDB('IP', src_mac, dst_mac, src_ip, dst_ip, None, None, ip_flags, packettype,actiontaken)
                if p.protocol_name == 'icmp':
#                     print 'icmp type = ', p.type
#                     print 'icmp code = ', p.code
#                     print 'icmp data = ', p.data
                      global src_ip #--sn
		      global dst_ip #--sn  

		      if p.type is not None:	
			 icmp_type = 'ICMP TYPE = '+ str(p.type)
		      else:
			 icmp_type = p.type
                      self.writeToDB('ICMP', src_mac, dst_mac, src_ip, dst_ip, None, None, icmp_type, packettype,actiontaken)
                if p.protocol_name == 'tcp':
                      #print 'tcp src port = ', p.src_port
                      #print 'tcp dst port = ', p.dst_port
                      #print 'tcp options = ', p.option
                      global src_ip #--sn
		      global dst_ip #--sn  
                      if p.option is not None: 
			 tcp_options = 'TCP OPTIONS = '+ str(p.option)
		      else:
			 tcp_options = p.option	
                      #print 'In SimplePacket Parser Before WriteToDB Call'
                      self.writeToDB('TCP', src_mac, dst_mac, src_ip, dst_ip, p.src_port, p.dst_port,tcp_options, packettype,actiontaken)
                if p.protocol_name == 'udp':
                     global src_ip #--sn
		     global dst_ip #--sn  
                     self.writeToDB('UDP', src_mac, dst_mac, src_ip, dst_ip,p.src_port,p.dst_port,None, packettype,actiontaken)
       	

    @handler.set_ev_cls(dpset.EventDP)
    def dp_handler(self, ev):
        if not ev.enter:
            return

        dp = ev.dp
        match = dp.ofproto_parser.OFPMatch()
        self.del_flow(dp,match)

    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        reason = msg.reason                    

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
  
        global good_pkt
	good_pkt = True
	

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})


                
        if reason == ofproto_v1_3.OFPR_ACTION:
            self.ids_monitor.check_packet(msg)  
            self.logger.info(" ~~~~ packet in %s %s %s %s %s %s", dpid, src, dst, in_port,src_ip,dst_ip) #--Rash

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

	good_pkt = self.chk_pkt_value()  
	#Initialize the file
	f = open('/home/rashmi/RYU295/ryu/lib/ids/pkt_value.txt', 'w').close()
	
	data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            print "Actions taken: "
            if good_pkt:

	       global src_ip
	       global dst_ip
	       global host_name
	       # Initialize the host log file
	       print " ~~~~ Packet is good" # set the actions accordingly
               actiontaken = "Packet forwarded"
	       packettype = "Good packet"
	       self.packetParser(msg,packettype,actiontaken) 
               self.get_host_name(src_ip)
	       f = open('/home/rashmi/RYU295/ryu/lib/ids/hosts_log/host%s.txt' % host_name, 'w').close()
	       #Validate host before deciding the actions based on its history no of pkts , put the condition after that bfr actions
	       is_good_host,allow_host[int(host_name)] = self.validate_host(src_ip, host_name,bad_pkt_limit) 


	       match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src = src_ip, ipv4_dst=dst_ip ) 
	       actions = [parser.OFPActionOutput(out_port)]
               out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                      in_port=in_port, actions=actions, data=data)
               datapath.send_msg(out)

               m = str(match)
               f = open('/home/rashmi/RYU295/ryu/lib/switch_flows.txt', 'a')
	       f.write("\n")
               f.write(m)
	       f.close()      
                   

	       if(allow_host[int(host_name)] == True):
	         actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		 self.flow_consistency_check(datapath,match,actions,out_port,host_name) 
	       else:
		 self.logger.info("Cumulative packet count exceed threshold for host %s *** Blocking this host ***",host_name)
	         actions = [parser.OFPActionOutput(ofproto.OFPC_FRAG_DROP)]
        	 inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
                 mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                match=match, instructions=inst,hard_timeout = 60)
                 datapath.send_msg(mod)
		       
   	    else:
	       global src_ip
	       global dst_ip
	       global host_name
	       global bad_pkt_limit
	       global allow_host
	       print " ~~~ Packet is bad" 
               actiontaken = "Packet dropped"
	       packettype = "Malicious packet"
               self.packetParser(msg,packettype,actiontaken)
               self.get_host_name(src_ip)
	       f = open('/home/rashmi/RYU295/ryu/lib/ids/hosts_log/host%s.txt' % host_name, 'a')
	       f.write("\n")
	       f.write("bad")
	       f.close()

	       #Validate host before deciding the actions based on its history of pkts , put the condition after that bfr actions
	       is_good_host,allow_host[int(host_name)] = self.validate_host(src_ip,host_name,bad_pkt_limit) 
	       if (is_good_host == False):
		  print "Host is malicious "

 		  match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src = src_ip, ipv4_dst=dst_ip ) 
	          actions = [parser.OFPActionOutput(ofproto.OFPC_FRAG_DROP)] 
                  
                  '''m = str(match)
                  f = open('/home/rashmi/RYU295/ryu/lib/switch_flows.txt', 'a')
	          f.write("\n")
	          f.write(m)
	          f.close() '''       		  

                  self.flow_consistency_check(datapath,match,actions,out_port,host_name)  
		  
	       else:

 		  match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src = src_ip, ipv4_dst=dst_ip ) 
                  
                  '''m = str(match)
                  f = open('/home/rashmi/RYU295/ryu/lib/switch_flows.txt', 'a') 
	          f.write("\n")
	          f.write(m)
	          f.close()   '''

	          if(allow_host[int(host_name)] == True):
	            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		    self.flow_consistency_check(datapath,match,actions,out_port,host_name)
	          else:
		    self.logger.info("Cumulative packet count exceed threshold for host %s *** Blocking this host ***",host_name)
	            actions = [parser.OFPActionOutput(ofproto.OFPC_FRAG_DROP)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                match=match, instructions=inst, hard_timeout = 60)
                    datapath.send_msg(mod)

		  
       
        data = None
        actions = " "
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        if reason != ofproto_v1_3.OFPR_ACTION:
            self.ids_monitor.check_packet(msg)
            self.logger.info(" ~~~~ packet in %s %s %s %s %s %s", dpid, src, dst, in_port, src_ip,dst_ip)
            
	    good_pkt = self.chk_pkt_value() 
	    #Initialize the file
	    f = open('/home/rashmi/RYU295/ryu/lib/ids/pkt_value.txt', 'w').close()

            if good_pkt:
	       print " ~~~ Packet is good" 
               actiontaken = "Packet forwarded"
	       packettype = "Good packet"
               self.packetParser(msg,packettype,actiontaken)
	       global host_name
	       global allow_host
	       self.get_host_name(src_ip) 

	       f = open('/home/rashmi/RYU295/ryu/lib/ids/hosts_log/host%s.txt' % host_name, 'w').close()
	       actions = [parser.OFPActionOutput(out_port)]

 	       match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src = src_ip, ipv4_dst=dst_ip )
               out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                      in_port=in_port, actions=actions, data=data)
               datapath.send_msg(out)
               
                  

	       if(allow_host[int(host_name)] == True):
	          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
 		  self.flow_consistency_check(datapath,match,actions,out_port,host_name)
	       else:
		  self.logger.info("Cumulative packet count exceed threshold for host %s *** Blocking this host ***",host_name)
	          actions = [parser.OFPActionOutput(ofproto.OFPC_FRAG_DROP)]
                  inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
                  mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                match=match, instructions=inst,hard_timeout = 60)
                  datapath.send_msg(mod)

	       
             	       
   	    else:
	       global src_ip
	       global dst_ip
	       global host_name
	       global bad_pkt_limit
	       print " ~~~ Packet is bad" # set the actions accordingly
               actiontaken = "Packet dropped"
	       packettype = "Malicious packet"
               self.packetParser(msg,packettype,actiontaken)
               self.get_host_name(src_ip)
	       f = open('/home/rashmi/RYU295/ryu/lib/ids/hosts_log/host%s.txt' % host_name, 'a')
	       f.write("\n")
	       f.write("bad")
	       f.close()
               
	       #Validate host before deciding the actions based on its history of pkts , put the condition after that bfr actions
	       is_good_host = self.validate_host(src_ip, host_name,bad_pkt_limit) 
	       if (is_good_host == False):  #host will be permanently blocked
		  print "Host is malicious "
          
 		  match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src = src_ip, ipv4_dst=dst_ip )
                  actions = [parser.OFPActionOutput(ofproto.OFPC_FRAG_DROP)]
                  
                  self.flow_consistency_check(datapath,match,actions,out_port,host_name) 
		 
	       else:

 		  match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src = src_ip, ipv4_dst=dst_ip ) 
                  

	          if(allow_host[int(host_name)] == True):
	            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
		    self.flow_consistency_check(datapath,match,actions,out_port,host_name)
	          else:
	            self.logger.info("Cumulative packet count exceed threshold for host %s *** Blocking this host ***",host_name)
	            actions = [parser.OFPActionOutput(ofproto.OFPC_FRAG_DROP)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                match=match, instructions=inst)
                    datapath.send_msg(mod)


		 
	
        
    @set_ev_cls(ids_monitor.AttackAlert)
    def _dump_alert(self, ev):  
        alertmsg = ev.alertmsg
        msg = ev.data

        print '---------------alertmsg:', ''.join(alertmsg)


    def writeToDB(self, protocol, srcmac, dstmac, srcip, dstip, srcport, dstport, options, packettype,actiontaken): 
        dbcon = mdb.connect("localhost","testuser","test123","attackdb" )
        cursor = dbcon.cursor()
    

	
        try:
	    #print 'Inside Try Block'
	    #print 'Protocol:',protocol
	    #print 'srcmac:',srcmac
            #print 'dstmac:',dstmac
            #print 'srcip:',srcip
            #print 'dstip:',dstip
            #print 'srcport:',srcport
            #print 'dstport:',dstport
            #print 'options:',options 		
            cursor.execute("INSERT INTO packets(protocol,sourcemac, destmac, sourceip, destip, sourceport, destport, options,packettype,actiontaken)VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(protocol, srcmac, dstmac, srcip, dstip, srcport, dstport, options,packettype,actiontaken))
            dbcon.commit()
        except:
	    #print 'Inside Exception block'	
            dbcon.rollback()
