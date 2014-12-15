from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from . import ids_utils
from . import BoyerMooreStringSearch
import MySQLdb as mdb

class tcp(object):
    
    def __init__(self,packet_data):
        self.packet_data =  packet.Packet(packet_data.data)  
        self.dst_ip = ids_utils.get_packet_dst_ip_address(self.packet_data)
        self.src_ip = ids_utils.get_packet_src_ip_address(self.packet_data)
        self.dst_port = ids_utils.get_packet_dst_port(self.packet_data)
        self.src_port = ids_utils.get_packet_src_port(self.packet_data)
        self.length_data = ids_utils.get_packet_length(self.packet_data)
	self.tcp_bits = ids_utils.get_packet_tcp_control_bits(self.packet_data)      

    def check_packet(self,mode,src_ip, src_port, dst_ip, dst_port,rule_type,pattern,depth,offset,flags,rule_msg): 
        for p in self.packet_data:
            if hasattr(p, 'protocol_name') is True:
                #print p.protocol_name
                if p.protocol_name == 'tcp':
                     match = self.check_tcp_ip_port_match(src_ip, src_port, dst_ip, dst_port,flags)
                     match_content = True
                     pkt_contents = ""  
                     if match == True:
                         length = ids_utils.get_packet_length(self.packet_data)
			 #print 'Length= ', length
                         for p in self.packet_data.protocols:
                             if hasattr(p, 'protocol_name') is False:
                                 #print 'Value of P in tcp.py ', p
                                 #ids_utils.print_packet_data(p, length)
                                 contents=ids_utils.get_packet_data(p,length)
                                 pkt_contents = str(contents)
                                 #print 'pkt_contents ', pkt_contents
                                 #print pattern
				 if offset is not None:
                                    pkt_contents = pkt_contents[offset:]
				 if depth is not None:
                                    pkt_contents = pkt_contents[:depth]
                             if pattern is not None:
				 for p in pattern:
                                 #match_content = BoyerMooreStringSearch.BMSearch(pkt_contents,pattern)
                                 	match_content = pkt_contents.find(p)
					if match_content == -1:
                                           break
                             #if match_content == True:
                             if match_content != -1:
                                 f = open('/home/ubuntu/RYU295/ryu/lib/ids/log.txt', 'a')
                                 f.write("\n")
                                 f.write(rule_msg)
                                 f.close()
                                 self.writeToDB('TCP Attack Packet', 'tcp',rule_msg, 
                                                self.src_ip, self.dst_ip, self.src_port, self.dst_port)
                                 #print 'After Call to Print Packet Data in TCP'
                             #if mode == 'alert' and match_content == True:
                             if mode == 'alert' and match_content != -1:
                                 #print 'TCP Attack Packet'
                                 alertmsg = rule_msg
                                 return alertmsg
     
     
                                
    def check_tcp_ip_port_match(self,src_ip, src_port, dst_ip, dst_port,flags):

        #print 'Print message from tcp.py'
        #print 'packet source', self.src_ip
        #print 'packet dst', self.dst_ip
        #print 'rule source', src_ip
        #print 'rule dst', dst_ip
        #print 'Print Message from tcp.py Ends'
	bits=[]
	fin_bit = self.tcp_bits & 1
	if fin_bit ==1:
	   bits.append('F')
		
	syn_bit = (self.tcp_bits>>1) & 1
	if syn_bit==1:
	   bits.append('S')
        
	#print 'Flags: ', flags

        if (('any' in src_ip) or (self.src_ip in src_ip)):
            if (('any' in dst_ip) or (self.dst_ip in dst_ip)):
                if ((src_port == 'any') or (int(src_port) == int(self.src_port))):
                    if ((dst_port == 'any') or (int(dst_port) == int(self.dst_port))):
		       if flags is not None:
			  for b in flags:
			    if not b in bits:
				  return False
                       x=True
		       return x

	
    
    def writeToDB(self,name, protocol, msg, srcip, dstip, srcport, dstport): 
        dbcon = mdb.connect("localhost","testuser","test123","attackdb" )
        cursor = dbcon.cursor()
        try:
            cursor.execute("INSERT INTO attacks(name,protocol, message, sourceip, destip, sourceport, destport)VALUES (%s, %s,%s, %s, %s,%s,%s)",(name, protocol, msg, srcip, dstip, srcport, dstport))
            dbcon.commit()
        except:
            dbcon.rollback()

      
