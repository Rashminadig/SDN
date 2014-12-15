from ryu.lib.packet import packet
from . import ids_utils
from . import BoyerMooreStringSearch
import MySQLdb as mdb

class icmp(object):
    
    def __init__(self,packet_data):
        self.packet_data =  packet.Packet(packet_data.data)  
        self.dst_ip = ids_utils.get_packet_dst_ip_address(self.packet_data)
        self.src_ip = ids_utils.get_packet_src_ip_address(self.packet_data)
        self.rule_type = ids_utils.get_packet_type(self.packet_data)
        self.src_port = ids_utils.get_packet_src_port(self.packet_data)
        self.dst_port = ids_utils.get_packet_dst_port(self.packet_data)


    def check_packet(self,mode,src_ip, src_port, dst_ip, dst_port,rule_type,pattern,depth,offset,flags,rule_msg): 
        for p in self.packet_data:
            if hasattr(p, 'protocol_name') is True:
                #print p.protocol_name
                if p.protocol_name == 'icmp':
                     #print 'p.data: ', p.data
                     #print p.data
                     match = self.check_ip_match(src_ip, dst_ip,rule_type)
		     #print 'From ICMP Class : Match'
		     #print match
     		     pkt_contents=""
		     if match == True:
                         length = ids_utils.get_packet_length(self.packet_data)
                         #print 'length: '
                         #print length
                         #for p in self.packet_data.protocols:
                         #for p in self.packet_data:
                             #print 'p: '
                             #print p
                             #if hasattr(p, 'protocol_name') is False:
                             #if p.protocol_name == 'ipv4':
                         #print 'Before Call to Print Packet Data in ICMP'
                               #ids_utils.print_packet_data(str(p), length)
                         #ids_utils.print_packet_data(str(p.data), length)
                                 #pkt_contents=ids_utils.get_packet_data(str(p),length)
                         contents = ids_utils.get_packet_data(str(p.data),length)
			 pkt_contents = str(contents)
	
			 #ignore the first 11 characters consisting of the string echo(data='	
			 pkt_contents = pkt_contents[11:]

			 if offset is not None:
                                    pkt_contents = pkt_contents[offset:]
                         if depth is not None:
                                    pkt_contents = pkt_contents[:depth]
                         
			 #print 'Pattern: '
                         #print pattern
                         if pattern is not None:
		            for p in pattern:
                                 #match_content = BoyerMooreStringSearch.BMSearch(pkt_contents,pattern)
				  match_content = pkt_contents.find(p)
				  if match_content == -1:
                                           break
			 else:
			      # if pattern is None just set the match_content to True Value(1)	
			      match_content = 1	
                         #print 'match_content: '
                         #print match_content
                         #if match_content == True:
                         if match_content != -1:
                                 f = open('/home/ubuntu/RYU295/ryu/lib/ids/log.txt', 'a')
                                 f.write("\n")
				 f.write(rule_msg)
                                 f.close()
                                 self.writeToDB('ICMP Attack Packet', 'icmp',rule_msg, 
                                                self.src_ip, self.dst_ip, self.src_port, self.dst_port)
                                 #print 'After Call to Print Packet Data in TCP'
                         #if mode == 'alert' and match_content == True:
                         if mode == 'alert' and match_content != -1:
                                 #print 'TCP Attack Packet'
                                 alertmsg = rule_msg
                                 return alertmsg		
                                
    def check_ip_match(self,src_ip, dst_ip,rule_type):
        #print 'packet source', self.src_ip
        #print 'packet dst', self.dst_ip
        #print 'packet rule ', self.rule_type
        #print 'rule source', src_ip
        #print 'rule dst', dst_ip
        #print 'rule type ', rule_type
        #print 'Print Message from ICMP Module'
        if (('any'in src_ip) or (self.src_ip in src_ip)):
            if (('any' in dst_ip) or (self.dst_ip in dst_ip)):
		if(self.rule_type == rule_type):
                    return True

    def writeToDB(self,name, protocol, msg, srcip, dstip,srcport, dstport): 
        dbcon = mdb.connect("localhost","testuser","test123","attackdb" )
        #with dbcon:
	cursor = dbcon.cursor()
       	try:
	       #print 'In Try Block of WriteToDB'	
               cursor.execute("INSERT INTO attacks(name,protocol, message, sourceip, destip, sourceport, destport)VALUES (%s, %s,%s, %s, %s, %s, %s)",(name, protocol, msg, srcip, dstip, srcport, dstport))
               dbcon.commit()
        except:
	       #print 'In Rollback Block'	
               dbcon.rollback()
       

