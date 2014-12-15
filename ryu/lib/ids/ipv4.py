from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from . import ids_utils
from . import BoyerMooreStringSearch
import MySQLdb as mdb

class ipv4(object):
    
    def __init__(self,packet_data):
        self.packet_data =  packet.Packet(packet_data.data)      
        self.dst_ip = ids_utils.get_packet_dst_ip_address(self.packet_data)
        self.src_ip = ids_utils.get_packet_src_ip_address(self.packet_data)
        #self.dst_port = ids_utils.get_packet_dst_port(self.packet_data)
        #self.src_port = ids_utils.get_packet_src_port(self.packet_data)
        self.length_data = ids_utils.get_packet_length(self.packet_data)

    #def check_packet(self,mode,src_ip, src_port, dst_ip, dst_port,pattern):
    def check_packet(self,mode,src_ip, src_port, dst_ip, dst_port,rule_type,pattern,depth,offset,flags,rule_msg):    
        for p in self.packet_data:
            if hasattr(p, 'protocol_name') is True:
                #print p.protocol_name
                if p.protocol_name == 'ipv4':
                     match = self.check_ip_match(src_ip, dst_ip)
                     match_content = True
                     pkt_contents=""
                     if match == True:
                         length = ids_utils.get_packet_length(self.packet_data)
                         for p in self.packet_data.protocols:
                             if hasattr(p, 'protocol_name') is False:
                                 #print 'Before Call to Print Packet Data in IPV4'
                                 #ids_utils.print_packet_data(p, length)
                                 #print 'p in icmp.py: ', p
                                 #print 'length: ',length
                                 contents=ids_utils.get_packet_data(p,length)
                                 pkt_contents = str(contents)
				 
				 if offset is not None:
                                    pkt_contents = pkt_contents[offset:]
                                 #print 'pkt_contents after offset:',pkt_contents
                                 if depth is not None:
                                    pkt_contents = pkt_contents[:depth]

                                 #print 'pkt_contents: ', pkt_contents
                                 #print 'pattern: ', pattern
                             if pattern is not None:
				 for p in pattern:
                                 #match_content = BoyerMooreStringSearch.BMSearch(pkt_contents,pattern)
                                 	match_content = pkt_contents.find(p)
					if match_content == -1:
                                           break
			     else:
				  match_content =1 	
                                 #print 'match_content: ', match_content
                             #if match_content == True:
                             if match_content != -1:
                                 f = open('/home/ubuntu/RYU295/ryu/lib/ids/log.txt', 'a')
                                 f.write("\n")
                                 f.write(rule_msg)
                                 f.close()
                                 self.writeToDB('IPv4 Attack Packet', 'IPv4',rule_msg,
                                                self.src_ip, self.dst_ip,8000,8000)
                                 #print 'After Call to Print Packet Data in IPV4'
                             if mode == 'alert' and match_content != -1:
                                 #print 'IPV4 Attack Packet'
                                 alertmsg = rule_msg
                                 return alertmsg
     
     
     
                                
    def check_ip_match(self,src_ip, dst_ip):
        # print 'packet source', self.src_ip
        #print 'packet dst', self.dst_ip
        #print 'rule source', src_ip
        #print 'rule dst', dst_ip
        if (('any' in src_ip) or (self.src_ip in src_ip)):
            if (('any' in dst_ip) or (self.dst_ip in dst_ip)):
                return True  

    def writeToDB(self,name, protocol, msg, srcip, dstip, srcport, dstport):
        dbcon = mdb.connect("localhost","testuser","test123","attackdb" )
        cursor = dbcon.cursor()
        try:
            cursor.execute("INSERT INTO attacks(name,protocol, message, sourceip, destip, sourceport, destport)VALUES (%s, %s,%s, %s, %s,%s,%s)",(name, protocol, msg, srcip, dstip, srcport, dstport))
            dbcon.commit()
        except:
            dbcon.rollback()


