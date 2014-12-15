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
# limitations under the License.s

from operator import attrgetter
from ryu.app import simple_switch_13_v6
#from ryu.app.simple_switch_13_v4 import SimpleSwitch13
#from ryu.app.simple_switch_13 import hosts
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


import collections


class RequestStats(simple_switch_13_v6.SimpleSwitch13):
	def __init__(self, *args, **kwargs):
		super(RequestStats, self).__init__(*args, **kwargs)
		self.datapaths = {}
		self.monitor_thread = hub.spawn(self._monitor)

	@set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
	def _state_change_handler(self, ev):
		datapath = ev.datapath
		if ev.state == MAIN_DISPATCHER:
			if not datapath.id in self.datapaths:
				self.logger.debug("register datapath: %016x", datapath.id)
				self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug("unregister datapath: %016x", datapath.id)
				del self.datapaths[datapath.id]

	def _monitor(self):
		#for dp in self.datapaths.values():
                #    self.send_table_stats_request(dp);
		while True:
			for dp in self.datapaths.values():
                                f = open('/home/rashmi/RYU295/ryu/lib/switch_flows.txt', "w+")
				f.write(" Switch flow entries")
                                f.write ( "\n" )
                                f.close() 
                                
				self._request_stats(dp)
				 

				
			hub.sleep(20)
        
	def _request_stats(self, datapath):
		self.logger.debug("send stats request: %016x", datapath.id)
		ofp = datapath.ofproto
		parser = datapath.ofproto_parser
		
		req = parser.OFPTableStatsRequest(datapath, 0)
		datapath.send_msg(req)
		#req = parser.OFPTableFeaturesStatsRequest(datapath,0)
			     
                #datapath.send_msg(req)
		


    		cookie = cookie_mask = 0
    		#match =  parser.OFPMatch(in_port=1)
		#if sum(simple_switch_13_v4.hosts.values()) == 0:
    		req = parser.OFPFlowStatsRequest(datapath, 0,
                                         0, #ofp.OFPTT_ALL,
					 ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         cookie, cookie_mask)#,
                #                         match)
		datapath.send_msg(req)




											
	def send_table_stats_request(self, datapath):
    		ofp = datapath.ofproto
	    	ofp_parser = datapath.ofproto_parser
		self.logger.debug("send features stats request: %016x", datapath.id)
		req = ofp_parser.OFPTableFeaturesStatsRequest(datapath,0)

    		#req = ofp_parser.OFPTableStatsRequest(datapath, 0)
    		datapath.send_msg(req)

	@set_ev_cls(ofp_event.EventOFPTableFeaturesStatsReply, MAIN_DISPATCHER)
        def table_features_stats_reply_handler(self, ev):
                tables = []
                print'Hello....'
                		
                for stat in ev.msg.body:
                        tables.append("table_id=%d max_entries=%d "  %
                               (stat.table_id, stat.max_entries))
			break
                self.logger.info("Srila TablefeaturesStats: %s", tables)

	@set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
	def table_stats_reply_handler(self, ev):
    		tables = []
		
    		for stat in ev.msg.body:
        		tables.append("table_id=%d active_count=%d " %
                      		(stat.table_id, stat.active_count))
     		self.logger.info("TableStats: %s", tables[0])
	#print "tables...",tables




	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply_handler(self, ev):
    	    flows = []
	#    for stat in ev.msg.body:
	
	   # packet_threshold = 5
	    body = ev.msg.body
	    datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
	 
	    self.logger.info('Flow Statistics:')
	    self.logger.info("table_id in_port   Port    priority packet_count ip_address   ")
            self.logger.info("-------- -------- -------- -------- ------------ ------------")

	    sritest = 0
	    for j in simple_switch_13_v6.hosts:
	 	simple_switch_13_v6.hosts[j] = 0
            	simple_switch_13_v6.newhosts[j] = 0
	    
	    for stat in sorted([flow for flow in body if flow.priority == 1]):

        	self.logger.info("%4d %10d %10d %8d %8d %10s " %
                     #'match=%s instructions=%s' %
                     (stat.table_id,
                      ##stat.duration_sec, stat.duration_nsec,
		      stat.match['in_port'],
		      #stat.match['ipv4_src'],
                      stat.instructions[0].actions[0].port,
                      stat.priority,
                      stat.packet_count,stat.match['ipv4_src']))
		if(stat.match['ipv4_src'] != '10.0.0.2' and stat.instructions[0].actions[0].port !=1):
			if(stat.match['ipv4_src'] in simple_switch_13_v6.newhosts.keys()):
				sritest = simple_switch_13_v6.newhosts[stat.match['ipv4_src']]
			simple_switch_13_v6.newhosts[stat.match['ipv4_src']] = stat.packet_count  + sritest 

                	

                #print " --------- Adding match conditions to file "
                m = str(stat.match)                                                   
                f = open('/home/rashmi/RYU295/ryu/lib/switch_flows.txt', 'a')  
	        f.write("\n")
	        f.write(m)
	        f.close()   
	    

	    #self.logger.info("Srilatha .... Before Sort")
	    for j in simple_switch_13_v6.newhosts:
                self.logger.info("Ip-address= %s,Total Packet-count= %d",j,simple_switch_13_v6.newhosts[j])
 	    
	    simple_switch_13_v6.hosts = {key: simple_switch_13_v6.newhosts[key] - simple_switch_13_v6.oldhosts.get(key, 0) for key in simple_switch_13_v6.newhosts.keys()}
            
	    for j in simple_switch_13_v6.hosts:
		if simple_switch_13_v6.hosts[j] <0:
		    simple_switch_13_v6.hosts[j] = 0		

            for j in simple_switch_13_v6.hosts:
		 self.logger.info("********************************************")
                 self.logger.info("Ip-address= %s,latest total Packet-count= %d",j,simple_switch_13_v6.newhosts[j])
                 #self.logger.info("Ip-address= %s,previous total Packet-count= %d",j,simple_switch_13_v6.oldhosts[j])
                 self.logger.info("Ip-address= %s,current interval Packet-count= %d",j,simple_switch_13_v6.hosts[j])
	         self.logger.info("********************************************")
	    for j in simple_switch_13_v6.newhosts:
                simple_switch_13_v6.oldhosts[j] = simple_switch_13_v6.newhosts[j]
		#self.logger.info("Ip-address= %s,previous total Packet-count= %d",j,simple_switch_13_v6.oldhosts[j])
							
	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def _port_stats_reply_handler(self, ev):
		body = ev.msg.body
		self.logger.info("datapath              port    " 
				  "rx-pkts "
				  "tx-pkts")
		self.logger.info("----------------    -------- "
						"-------- "
						"--------")
		for stat in sorted(body, key=attrgetter("port_no")):
			self.logger.info("%016x %8x %8d %8d",
							ev.msg.datapath.id, stat.port_no,
							stat.rx_packets,
							stat.tx_packets)															

