import struct
from ryu.lib.packet import stream_parser

UNPACK_STR = '!%ds'

def get_packet_dst_ip_address(pkt):
    for p in pkt:
            if hasattr(p, 'protocol_name') is True:
                if p.protocol_name == 'ipv4':
                    p_dst = p.dst
                    return p_dst
    return None



def get_packet_src_ip_address(pkt):
    for p in pkt:
            if hasattr(p, 'protocol_name') is True:
                if p.protocol_name == 'ipv4':
                    p_src = p.src
                    return p_src
    return None


def get_packet_dst_port(pkt):
    for p in pkt:
            if hasattr(p, 'protocol_name') is True:
                if p.protocol_name == 'tcp' or p.protocol_name== 'udp':
                    p_dstport = p.dst_port
                    return p_dstport
    return None


def get_packet_src_port(pkt):
    for p in pkt:
            if hasattr(p, 'protocol_name') is True:
                if p.protocol_name == 'tcp' or p.protocol_name== 'udp':
                    p_srcport = p.src_port
                    return p_srcport
    return None

def get_packet_tcp_control_bits(pkt):
    for p in pkt:
            if hasattr(p, 'protocol_name') is True:
                if p.protocol_name == 'tcp':
                    p_bits = p.bits
                    return p_bits
    return None

def get_packet_length(pkt):
    for p in pkt:
            if hasattr(p, 'protocol_name') is True:
                #if p.protocol_name == 'ip':
                if p.protocol_name == 'ipv4':
                    p_length = p.total_length
                    return p_length
    return 0

def get_packet_type(pkt):
    for p in pkt:
            if hasattr(p, 'protocol_name') is True:
                if p.protocol_name == 'icmp':
                    p_type = str(p.type)
 		    #print 'Type From ids utils'
		    #print p_type
                    return p_type
    return None

def get_icmp_packet_data(buf):
    #for p in pkt:
           # if hasattr(p, 'protocol_name') is True:
               # if p.protocol_name == 'icmp':
			#buf = p.data
		    	unpack_str = UNPACK_STR % (len(buf))
		    	pac_len = struct.calcsize(unpack_str)
    		    	if len(buf) < pac_len:
           			 raise stream_parser.StreamParser.TooSmallException(
                			'%d < %d' % (len(buf), pac_len))
    		   	#print 'unpack string : ' , unpack_str
    		    	data_string = "".join(struct.unpack_from(unpack_str, buf))
                    	#print 'Data From ids utils'
                        #print data_string
                  	return data_string
 		
			#return None


def print_packet_data(buf, total_lenth):
    #print 'Contents of Buffer in Print_Packet_data ', str(buf)
    unpack_str = UNPACK_STR % (len(buf))
    pac_len = struct.calcsize(unpack_str)
    if len(buf) < pac_len:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), pac_len))
    #print 'unpack string : ' , unpack_str
    #print 'Print Message in ids_utils start'
    data_string = struct.unpack_from(unpack_str, buf)
    print 'data string : ', data_string
   # return data_string

def get_packet_data(buf, total_lenth):
    unpack_str = UNPACK_STR % (len(buf))
    pac_len = struct.calcsize(unpack_str)
    if len(buf) < pac_len:
            raise stream_parser.StreamParser.TooSmallException(
                '%d < %d' % (len(buf), pac_len))
    #print 'unpack string : ' , unpack_str
    data_string = "".join(struct.unpack_from(unpack_str, buf))
    return data_string 	
