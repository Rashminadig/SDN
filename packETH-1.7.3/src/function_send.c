/*
 * packETH - ethernet packet generator
 * By Miha Jemec <jemcek@gmail.com>
 * Copyright 2003 Miha Jemec, Iskratel
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * function_send.c - routines for sending packet
 *
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include <unistd.h>
#include <sys/types.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include "callbacks.h"
#include "function_send.h"
#include "function.h"

#include <sys/time.h>

extern int number;
extern unsigned char packet[10000];
extern gboolean stop_flag;
//extern char iftext[20];
char iftext[20];

struct params  {
        long del;
        double count;
        int inc;
	int type;
        GtkWidget *button;
        GtkWidget *button1;
        GtkWidget *button2;
        GtkWidget *button3;
        GtkWidget *button4;
        GtkWidget *button5;
        GtkWidget *button6;
        GtkWidget *toolbar;
        GtkWidget *stopbt;
        gint context_id;
        gint timeflag;
	gint random;
        int udpstart;
        int tcpstart;
        int ipstart;
        int ethstart;
	int xbyte;
        int ybyte;
        int xchange;
        int ychange;
	unsigned long xrange;
        unsigned long yrange;
	char xstart[4];
	char ystart[4];
	unsigned char pkttable[10][10000];
        long int partable[10][6];
};
/* end */


/* go men go! */
int packet_go_on_the_link(unsigned char *pkt, int nr)
{
	int c, fd;
	struct sockaddr_ll sa;
	struct ifreq ifr;
        char buff[100];
	
	/* do we have the rights to do that? */
	if (getuid() && geteuid()) {
		//printf("Sorry but need the su rights!\n");
		error("Sorry but need the su rights!");
		return -2;
	}
	
	/* open socket in raw mode */
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd == -1) {
		//printf("Error: Could not open socket!\n");
		error("Error: Could not open socket!");
		return -2;
	}

	/* which interface would you like to use? */
	memset(&ifr, 0, sizeof(ifr));
	strncpy (ifr.ifr_name, iftext, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		//printf("No such interface: %s\n", iftext);
		snprintf(buff, 100, "No such interface: %s", iftext);
		error(buff);
		close(fd);
		return -2;
	}	

	/* is the interface up? */
        ioctl(fd, SIOCGIFFLAGS, &ifr);
	if ( (ifr.ifr_flags & IFF_UP) == 0) {
                //printf("Interface %s is down\n", iftext);
		snprintf(buff, 100, "Interface %s is down", iftext);
               	error(buff);
                close(fd);
                return -2;
        }

	/* just write in the structure again */
        ioctl(fd, SIOCGIFINDEX, &ifr);
	
	/* well we need this to work */
	memset(&sa, 0, sizeof (sa));
	sa.sll_family    = AF_PACKET;
	sa.sll_ifindex   = ifr.ifr_ifindex;
	sa.sll_protocol  = htons(ETH_P_ALL);

	c = sendto(fd, pkt, nr, 0, (struct sockaddr *)&sa, sizeof (sa));

	//printf("There were %d bytes sent on the wire (in case of an error we get -1)\n", c);

	if (close(fd) == 0) {
        	return (c);
	}
	else {
		//printf("Warning! close(fd) returned -1!\n");
		error("Warning! close(fd) returned -1!");
        	return (c);
	}

}


/* thread for sending packets */
void* sendbuilt (void *parameters)
{
	/* YYY check if li,... are long enough if inifinite number will be sent. Maybe put them into double */
        long li, gap = 0, gap2 = 0, sentnumber = 0, lastnumber = 0, seconds = 0;
        struct timeval nowstr, first, last;
        int c, fd, odd=0, actualnumber, correctcks = 0;
	unsigned int mbps, pkts, link;
	unsigned long xc=0, yc=0;
        char buff[100];
	struct sockaddr_ll sa;
        struct ifreq ifr;
	guint32 ipcks, pseudo_header, udpcksum, tcpcksum;
	guint32 *stevec32;

        struct params* p = (struct params*) parameters;

        /* do we have the rights to do that? */
        if (getuid() && geteuid()) {
		gdk_threads_enter ();
			snprintf(buff, 100, "  Problems with sending");
                	gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);
                	error("Sorry but need the su rights!");
		gdk_threads_leave ();
                return NULL;
        }

        /* open socket in raw mode */
        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd == -1) {
                //printf("Error: Could not open socket!\n");
		gdk_threads_enter ();
                        snprintf(buff, 100, "  Problems with sending");
                        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);
	                error("Error: Could not open socket!");
		gdk_threads_leave ();
                return NULL;
        }

	/* which interface would you like to use? */
        memset(&ifr, 0, sizeof(ifr));
        strncpy (ifr.ifr_name, iftext, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	/* does the interface exists? */
        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		gdk_threads_enter ();
                        snprintf(buff, 100, "  Problems with sending");
                        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);
                	snprintf(buff, 100, "No such interface: %s", iftext);
                	error(buff);
		gdk_threads_leave ();
                close(fd);
                return NULL;
        }

	/* is the interface up? */
        ioctl(fd, SIOCGIFFLAGS, &ifr);
	if ( (ifr.ifr_flags & IFF_UP) == 0) {
		gdk_threads_enter ();
                        snprintf(buff, 100, "  Problems with sending");
                        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);
                        snprintf(buff, 100, "Interface %s is down", iftext);
                	error(buff);
		gdk_threads_leave ();
                close(fd);
                return NULL;
        }

	/* just write in the structure again */
        ioctl(fd, SIOCGIFINDEX, &ifr);

        /* well we need this to work, don't ask me what is it about */
        memset(&sa, 0, sizeof (sa));
        sa.sll_family    = AF_PACKET;
        sa.sll_ifindex   = ifr.ifr_ifindex;
        sa.sll_protocol  = htons(ETH_P_ALL);

        /* this is the time we started */
        gettimeofday(&first, NULL);
        gettimeofday(&last, NULL);
        gettimeofday(&nowstr, NULL);

        /* to send first packet immediatelly */
        gap = p->del;

	/* if packet is shorter than 60 bytes, we need real packet length for calculating checksum,
	 * we use actualnumber for this */
	actualnumber = number;
	if (number < 60)
		number = 60;


	gtk_widget_set_sensitive (p->button1, FALSE);
	gtk_widget_set_sensitive (p->button2, FALSE);
	gtk_widget_set_sensitive (p->button3, FALSE);
	gtk_widget_set_sensitive (p->button4, FALSE);
	gtk_widget_set_sensitive (p->button5, FALSE);
	gtk_widget_set_sensitive (p->button6, FALSE);

	/* we check with == -3 if the infinite option was choosed */
        for(li = 0; p->count == -3 ? : li < p->count; li++) {
                while (gap < p->del) {
                        gettimeofday(&nowstr, NULL);

                        gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) -
                                                (last.tv_sec*1000000 + last.tv_usec);

                        gap2 = nowstr.tv_sec - first.tv_sec;

                        /* if the flag is set - the user clicked the stop button, we quit */
                        if (stop_flag == 1) {
                                gdk_threads_enter ();

				gtk_widget_set_sensitive (p->button1, TRUE);
				gtk_widget_set_sensitive (p->button2, TRUE);
				gtk_widget_set_sensitive (p->button3, TRUE);
				gtk_widget_set_sensitive (p->button4, TRUE);
				gtk_widget_set_sensitive (p->button5, TRUE);
				gtk_widget_set_sensitive (p->button6, TRUE);

                                snprintf(buff, 100, "  Sent %ld packets on %s", sentnumber, iftext);
                                gtk_statusbar_push(GTK_STATUSBAR(p->button),
                                                                GPOINTER_TO_INT(p->context_id), buff);

                                //gdk_flush();
				gdk_threads_leave ();
				close(fd);
                                return NULL;
                        }
                }

		c = sendto(fd, packet, number, 0, (struct sockaddr *)&sa, sizeof (sa));

		//printf("There were %d bytes sent on the wire (in case of an error we get -1)\n", c);

                last.tv_sec = nowstr.tv_sec;
                last.tv_usec = nowstr.tv_usec;
                gap = 0;

                if (c > 0)
                        sentnumber++;
//		else
//			break;

		 /* update the status bar every second and display number of sent packets */
                if (gap2 > seconds) {
                        gdk_threads_enter ();
			
			pkts = sentnumber - lastnumber;
			//mbps = pkts * number / 125000; // 8 bits per byte / 1000 for kbit
			mbps = pkts * number / 125; // 8 bits per byte / 1000 for kbit
			/* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                        link = pkts * (number + 24) / 125;
			lastnumber = sentnumber;

			snprintf(buff, 100, "  Sent %ld packets on %s (%d packets/s, %d kbit/s data rate, %d kbit/s link utilization)", sentnumber, iftext, pkts, mbps, link);
                        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);

                        //gdk_flush();
			gdk_threads_leave ();

                        seconds++;
                }

                /* do we need to change any fields */
		switch (p->inc) {
			/* changing source MAC address */
			case 1: {
				/*packet[6] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));*/
				packet[7] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[8] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[9] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[10] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[11] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				break;
			}
			/* change source IP address - make it random 
			 * and correct IP checksum, and tcp and udp if needed */
			case 2: {
				packet[p->ipstart] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+3] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				/* we have to correct the ip checksum 
				 * first we set 0x00 in both fields and then recalculate it */
        		        packet[p->ipstart-2] = 0x00;
                		packet[p->ipstart-1] = 0x00;
				ipcks = ((-1) - get_checksum16(p->ipstart-12, p->ipstart+7) % 0x10000);
        		        packet[p->ipstart-2] = (char)(ipcks/256);
                		packet[p->ipstart-1] =  (char)(ipcks%256);
				/* correct tcp or udp chechsum in needed */
				correctcks = 1;
				break;
			}
			/* source MAC address and source IP address 
			 * and correct IP checksum, and tcp and udp if needed */
			case 3: {
				/*packet[6] = 1+(int) (16.0*rand()/(RAND_MAX+1.0));*/
				packet[7] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[8] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[9] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[10] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[11] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+3] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				/* we have to correct the ip checksum 
				 * first we set 0x00 in both fields and then recalculate it */
        		        packet[p->ipstart-2] = 0x00;
                		packet[p->ipstart-1] = 0x00;
				ipcks = ((-1) - get_checksum16(p->ipstart-12, p->ipstart+7) % 0x10000);
        		        packet[p->ipstart-2] = (char)(ipcks/256);
                		packet[p->ipstart-1] =  (char)(ipcks%256);
				/* correct tcp or udp chechsum in needed */
				correctcks = 1;
				break;
			}
			/* for arp reply messages, change source MAC (ethernet part) *
			 * sender MAC and sender IP (arp part) */
			case 4: {
				//packet[p->ethstart] = 1+(int) (16.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+3] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+4] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+5] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+6] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+7] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+8] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+9] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				//packet[6] = packet[p->ethstart];
				packet[7] = packet[p->ethstart+1];
				packet[8] = packet[p->ethstart+2];
				packet[9] = packet[p->ethstart+3];
				packet[10] = packet[p->ethstart+4];
				packet[11] = packet[p->ethstart+5];
				break;
				
			}
			/* set random source TCP port and IP source address (syn flood) */ 
			case 5: {
				packet[p->ipstart] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ipstart+3] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->tcpstart] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->tcpstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				/* we have to correct the ip checksum 
				 * first we set 0x00 in both fields and then recalculate it */
        		        packet[p->ipstart-2] = 0x00;
                		packet[p->ipstart-1] = 0x00;
				ipcks = ((-1) - get_checksum16(p->ipstart-12, p->ipstart+7) % 0x10000);
        		        packet[p->ipstart-2] = (char)(ipcks/256);
                		packet[p->ipstart-1] =  (char)(ipcks%256);
				correctcks = 1;
				break;
			}
			/* increase the udp first payload byte value by one */
			case 6:  {
				packet[p->udpstart]++;
				correctcks = 1;
				break;
			}
			/* changing RTP values: seq number++, timestamp for 10ms */
			case 7: {
				packet[p->udpstart+2] = (li+1)/256;
				packet[p->udpstart+3] = (li+1)%256;
				packet[p->udpstart+4] = ((li+1)*80)/16777216;
				packet[p->udpstart+5] = ((li+1)*80)/65536;
				packet[p->udpstart+6] = ((li+1)*80)/256;
				packet[p->udpstart+7] = (signed int)(((li+1)*80)%256);
				correctcks = 1;
				break;
			}
			/* changing RTP values: seq number++, timestamp for 20ms */
			case 8: {
				packet[p->udpstart+2] = (li+1)/256;
				packet[p->udpstart+3] = (li+1)%256;
				packet[p->udpstart+4] = ((li+1)*160)/16777216;
				packet[p->udpstart+5] = ((li+1)*160)/65536;
				packet[p->udpstart+6] = ((li+1)*160)/256;
				packet[p->udpstart+7] = (signed int)(((li+1)*160)%256);
				correctcks = 1;
				break;
			}
			/* changing RTP values: seq number++, timestamp for 30ms */
			case 9: {
				packet[p->udpstart+2] = (li+1)/256;
				packet[p->udpstart+3] = (li+1)%256;
				packet[p->udpstart+4] = ((li+1)*240)/16777216;
				packet[p->udpstart+5] = ((li+1)*240)/65536;
				packet[p->udpstart+6] = ((li+1)*240)/256;
				packet[p->udpstart+7] = (signed int)(((li+1)*240)%256);
				correctcks = 1;
				break;
			}
			/* changing byte x value */
			case 10: {
				/* increment it within specified range */
				if (p->xchange == 1) {
					if (xc < (p->xrange)) {
						stevec32 = (guint32*) &packet[p->xbyte-1];
						(*stevec32)++;
						xc++;
					}
					else	{
						memcpy(&packet[p->xbyte-1], p->xstart, 4);
						xc=0;
					}
				}
				/* decrement it within specified range */
				else if (p->xchange == 2) {
					if (xc < (p->xrange)) {
						stevec32 = (guint32*) &packet[p->xbyte-1];
						(*stevec32)--;
						xc++;
					}
					else	{
						memcpy(&packet[p->xbyte-1], p->xstart, 4);
						xc=0;
					}
				}
				/* set it random */
				else if (p->xchange == 0)
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));

				else if (p->xchange == 3) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte-0] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	
					
				else if (p->xchange == 4) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	
					
				else if (p->xchange == 5) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	
					
				if(p->type >1) {
					packet[p->ipstart-2] = 0x00;
					packet[p->ipstart-1] = 0x00;
					ipcks = ((-1) - get_checksum16(p->ipstart-12, p->ipstart+7) % 0x10000);
					packet[p->ipstart-2] = (char)(ipcks/256);
					packet[p->ipstart-1] =  (char)(ipcks%256);
				}
				correctcks = 1;
				break;
			}
			/* change byte x and y */
			case 11: {
				/* byte x, increment */
				if (p->xchange == 1) {
					if (xc < (p->xrange)) {
						stevec32 = (guint32*) &packet[p->xbyte-1];
						(*stevec32)++;
						xc++;
					}
					else	{
						memcpy(&packet[p->xbyte-1], p->xstart, 4);
						xc=0;
					}
				}
				/* decrement it within specified range */
				else if (p->xchange == 2) {
					if (xc < (p->xrange)) {
						stevec32 = (guint32*) &packet[p->xbyte-1];
						(*stevec32)--;
						xc++;
					}
					else	{
						memcpy(&packet[p->xbyte-1], p->xstart, 4);
						xc=0;
					}
				}
				/* set it random */
				else if (p->xchange == 0)
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));

				else if (p->xchange == 3) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte-0] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	
					
				else if (p->xchange == 4) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	
					
				else if (p->xchange == 5) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	

				/* byte y increment */
				if (p->ychange == 1) {
					if (yc < (p->yrange)) {
						stevec32 = (guint32*) &packet[p->ybyte-1];
						(*stevec32)++;
						yc++;
					}
					else	{
						memcpy(&packet[p->ybyte-1], p->ystart, 4);
						yc=0;
					}
				}
				/* decrement it within specified range */
				else if (p->ychange == 2) {
					if (yc < (p->yrange)) {
						stevec32 = (guint32*) &packet[p->ybyte-1];
						(*stevec32)--;
						yc++;
					}
					else	{
						memcpy(&packet[p->ybyte-1], p->ystart, 4);
						yc=0;
					}
				}
				/* set it random */
				else if (p->ychange == 0)
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));

				else if (p->ychange == 3) {
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte-0] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	
					
				else if (p->ychange == 4) {
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	
					
				else if (p->ychange == 5) {
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}	

				if(p->type >1) {
					packet[p->ipstart-2] = 0x00;
					packet[p->ipstart-1] = 0x00;
					ipcks = ((-1) - get_checksum16(p->ipstart-12, p->ipstart+7) % 0x10000);
					packet[p->ipstart-2] = (char)(ipcks/256);
					packet[p->ipstart-1] =  (char)(ipcks%256);
				}

				correctcks = 1;
				break;
			}
		}

		/* correct the UDP checksum value???
		 * we do it (udp checksum in not mandatory (if set to 0x00)) */
		if (correctcks == 1) {
			if (p->type == 4) {
				packet[p->udpstart-2] = (char)(0);
				packet[p->udpstart-1] =  (char)(0);
				pseudo_header = (guint32)(packet[p->ipstart-3]);
				pseudo_header = pseudo_header + get_checksum32(p->ipstart,p->ipstart+7);
				udpcksum = (guint32)(actualnumber - p->udpstart +8);

				/* pseudo header (ip part) + udplength + nr of cicles over guint16 */
				udpcksum = pseudo_header + udpcksum;

				/* what if length is odd */
				if( (actualnumber - p->udpstart)%2 != 0) 
			                odd = 1;
				/* previos value + part from udp checksum */
				udpcksum = udpcksum + get_checksum32(p->udpstart-8, actualnumber+odd);
				while (udpcksum >> 16)
					udpcksum = (udpcksum & 0xFFFF)+(udpcksum >> 16);
	
					/* the one's complement */
				udpcksum = (-1) - udpcksum;
			
				/* let's write it */
				packet[p->udpstart-2] = (char)(udpcksum/256);
				packet[p->udpstart-1] =  (char)(udpcksum%256);
			}
			/* or tcp checksum*/
			else if (p->type == 3) {
				packet[p->tcpstart+16] = (char)(0);
				packet[p->tcpstart+17] =  (char)(0);
				pseudo_header = (guint32)(packet[p->ipstart-3]);
				pseudo_header = pseudo_header + get_checksum32(p->ipstart,p->ipstart+7);
				tcpcksum = (guint32)(actualnumber - p->tcpstart);
				/* pseudo header (ip part) + tcplength + nr of cicles over guint16 */
				tcpcksum = pseudo_header + tcpcksum;
				/* what if length is odd */
				if( (actualnumber - p->tcpstart)%2 != 0) 
			                odd = 1;
				/* previos value + part from tcp checksum */
				tcpcksum = tcpcksum + get_checksum32(p->tcpstart, actualnumber+odd);
				while (tcpcksum >> 16)
					tcpcksum = (tcpcksum & 0xFFFF) + (tcpcksum >> 16);
				/* the one's complement */
				tcpcksum = (-1) - tcpcksum;
				/* let's write it */
				packet[p->tcpstart+16] = (char)(tcpcksum/256);
				packet[p->tcpstart+17] =  (char)(tcpcksum%256);
			}
		}
        }

        /* we sent all the packets, let's activate the toolbar */
        gdk_threads_enter ();

	gtk_widget_set_sensitive (p->button1, TRUE);
	gtk_widget_set_sensitive (p->button2, TRUE);
	gtk_widget_set_sensitive (p->button3, TRUE);
	gtk_widget_set_sensitive (p->button4, TRUE);
	gtk_widget_set_sensitive (p->button5, TRUE);
	gtk_widget_set_sensitive (p->button6, TRUE);
//        gtk_widget_set_sensitive (p->stopbt, FALSE);

        snprintf(buff, 100, "  Sent %ld packets on %s", sentnumber, iftext);
        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);

	if (close(fd) != 0) {
		//printf("Warning! close(fd) returned -1!\n");
		error("Warning! close(fd) returned -1!");
	}

        //gdk_flush();
	gdk_threads_leave ();

        return NULL;

}


/* thread for sending sequences */
void* sendsequence (void *parameters)
{

	/* YYY check if li,... are long enough if inifinite number will be sent. Maybe put them into double */
        long li2, li=0, gap = 0, sentnumber = 0, seconds = 0, gap3 = 0, gap4 = 0, sentbytes = 0;
        struct timeval nowstr, nowstr1, first, first1, last, last1;
        int j, c, fd;
        char buff[100];
	struct sockaddr_ll sa;
        struct ifreq ifr;

        struct params* p = (struct params*) parameters;

        /* do we have the rights to do that? */
        if (getuid() && geteuid()) {
                //printf("Sorry but need the su rights!\n");
		gdk_threads_enter ();
                	
			snprintf(buff, 100, "  Problems with sending");
                	gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);

                	error("Sorry but need the su rights!");
		//gdk_flush();
		gdk_threads_leave ();
                return NULL;
        }

        /* open socket in raw mode */
        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd == -1) {
                //printf("Error: Could not open socket!\n");
		gdk_threads_enter ();

                        snprintf(buff, 100, "  Problems with sending");
                        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);

	                error("Error: Could not open socket!");
		//gdk_flush();
		gdk_threads_leave ();
                return NULL;
        }

	/* which interface would you like to use? */
        memset(&ifr, 0, sizeof(ifr));
        strncpy (ifr.ifr_name, iftext, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
                //printf("No such interface: %s\n", iftext);
		gdk_threads_enter ();

                        snprintf(buff, 100, "  Problems with sending");
                        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);

                	snprintf(buff, 100, "No such interface: %s", iftext);
			error(buff);
		//gdk_flush();
		gdk_threads_leave ();
                close(fd);
                return NULL;
        }

	/* is the interface up? */
        ioctl(fd, SIOCGIFFLAGS, &ifr);
	if ( (ifr.ifr_flags & IFF_UP) == 0) {
                //printf("Interface %s is down\n", iftext);
		gdk_threads_enter ();

                        snprintf(buff, 100, "  Problems with sending");
                        gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);

                	snprintf(buff, 100, "Interface %s is down", iftext);
                	error(buff);
		//gdk_flush();
		gdk_threads_leave ();
                close(fd);
                return NULL;
        }

	/* just write in the structure again */
        ioctl(fd, SIOCGIFINDEX, &ifr);

        /* well we need this to work, don't ask me what is it about */
        memset(&sa, 0, sizeof (sa));
        sa.sll_family    = AF_PACKET;
        sa.sll_ifindex   = ifr.ifr_ifindex;
        sa.sll_protocol  = htons(ETH_P_ALL);

        /* this is the time we started */
        gettimeofday(&first, NULL);
        gettimeofday(&last, NULL);

        /* to start first sequence immedialtelly */
        gap = p->del;

	gtk_widget_set_sensitive (p->button1, FALSE);
	gtk_widget_set_sensitive (p->button2, FALSE);
	gtk_widget_set_sensitive (p->button3, FALSE);
	gtk_widget_set_sensitive (p->button4, FALSE);
	gtk_widget_set_sensitive (p->button5, FALSE);
	gtk_widget_set_sensitive (p->button6, FALSE);
   // now it depends how to send all the streams.... 
   if (p->random == 0) {

	/* we check with == -3 if the infinite option was choosed */
	for (li = 1; p->count == -3 ? : li < p->count; li++) {
		/* so wait the delay between sequences */
		while (gap < p->del) {
			gettimeofday(&nowstr, NULL);
			gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) -
						(last.tv_sec*1000000 + last.tv_usec);

		}
		
		/* so we waited the desired time between sequences, now we go through all ten fields
		and send it if there is a name for a packet, and disable button is not on */
		for(j = 0; j < 10; j++) {
			/* skip it if there is no packet name */
			if (p->partable[j][0] == 0)
				continue;
			/* skip it if disable button is activated */
			if (p->partable[j][5] == 0)
				continue;

			/* now we are inside one sequence */
			/* this is the time we started */
			gettimeofday(&first1, NULL);
			gettimeofday(&last1, NULL);
			gettimeofday(&nowstr1, NULL);

			/* to send first packet immedialtelly */
			gap3 = p->partable[j][3];

			/* now we will send this packet partable[j][2] number of times */
			for (li2 = 0; li2 < p->partable[j][2]; li2++) {
				/* wait enough time */
				while (gap3 < p->partable[j][3]) {
					gettimeofday(&nowstr1, NULL);
					gap3 = (nowstr1.tv_sec*1000000 + nowstr1.tv_usec) -
							(last1.tv_sec*1000000 + last1.tv_usec);

				}

				/* put the packet on the wire */
				c = sendto(fd, p->pkttable[j], p->partable[j][1], 0, 
								(struct sockaddr *)&sa, sizeof (sa));

				last1.tv_sec = nowstr1.tv_sec;
				last1.tv_usec = nowstr1.tv_usec;
				gap3 = 0;

				if (c > 0) {
					sentnumber++;
					sentbytes = sentbytes + 24 + p->partable[j][1];
				}

				if (sentnumber == p->count) 
					goto out;

				gettimeofday(&nowstr, NULL);
				gap4 = nowstr.tv_sec - first.tv_sec;

				/* if the flag is set - the user clicked the stop button, we quit */
				if (stop_flag == 1) {
					gdk_threads_enter ();
	
					gtk_widget_set_sensitive (p->button1, TRUE);
					gtk_widget_set_sensitive (p->button2, TRUE);
					gtk_widget_set_sensitive (p->button3, TRUE);
					gtk_widget_set_sensitive (p->button4, TRUE);
					gtk_widget_set_sensitive (p->button5, TRUE);
					gtk_widget_set_sensitive (p->button6, TRUE);

					snprintf(buff, 100, "  Stoped... Completed %ld cycles.  Sent %ld packets on interface: %s", li,  sentnumber, iftext);
					gtk_statusbar_push(GTK_STATUSBAR(p->button),
									GPOINTER_TO_INT(p->context_id), buff);
	
					//gdk_flush();
					gdk_threads_leave ();
					close(fd);
					return NULL;
				}

				/* update the status bar every second and display number of sent packets */
				if (gap4 > seconds) {
					gdk_threads_enter ();

					snprintf(buff, 100, "   Sent %ld packets on interface: %s with rate %ld kbit/s", sentnumber, iftext, sentbytes/125);
					sentbytes=0;
					gtk_statusbar_push(GTK_STATUSBAR(p->button), 
								GPOINTER_TO_INT(p->context_id), buff);
	
					//gdk_flush();
					gdk_threads_leave ();

					seconds++;
				}
			}
			
			/* here we gonna wait the desired time before sending the next row */
			gettimeofday(&last1, NULL);
			gap3 = 0;

			while (gap3 < p->partable[j][4]) {

				gettimeofday(&nowstr1, NULL);
				gap3 = (nowstr1.tv_sec*1000000 + nowstr1.tv_usec) -
						(last1.tv_sec*1000000 + last1.tv_usec);

			}
		}		
	        gettimeofday(&last, NULL);
                gap = 0;
	}
    }
    //ok, whe want to send all the streams in some random way... now how random is the random question :)
    else {
	//rewrite and accept only the active streams
	unsigned char pkttmp[10][9300];
	int pktnr[10], pktlength[10]; 
	int pktnrstart[10]; 
	float summ=0; 
	int rnd, out=0, in=0, sum=0;
	//int delay;
	int table[10000];
	//lets copy only the active streams in a cont. table without gaps, might be easier and faster
	for (j=0; j<10; j++) {
		/* skip it if there is no packet name or disable is activated or 0 packets in that stream to send */
			if ((p->partable[j][0] == 0) || (p->partable[j][5] == 0) || (p->partable[j][2]== 0)  ) {
				pktnr[j] = 0;
				continue;
			}
			else {
				//copy packet contents
				memcpy(&pkttmp[j][0], &(p->pkttable[j][0]), p->partable[j][1]);
				//number of packets to send
				pktnr[j] = p->partable[j][2];
				pktnrstart[j] = p->partable[j][2];
				//totol number of packets (all strems)
				summ = summ + pktnr[j];
				sum = (int)summ;
				pktlength[j] = p->partable[j][1];
			}
	}

	//now... if we have more than 10000 packets, go out
	if (summ > 9999) {
		error("not enough memory...");
		return NULL;
	}
	//table(out) stores which stream will be sent from 1-10. If there are 5,3,1 packets from streams 1,2,3
	//there will be table(out)= 0,0,0,0,0,1,1,1,2     (stream 1 has number 0)
	else {
		for (j=0, out=0; j<10; j++) {
			for (in=0; in<pktnr[j]; in++)  {
				table[out]=j;
				out++;
			}
		}
	}

	for (;;) {
		
		gettimeofday(&last1, NULL);
		gap3 = 0;

		rnd= (int) (summ*rand()/(RAND_MAX+1.0));
		rnd = table[rnd];

		// if one "cycle" is over, we have to reset it
		if (sum == 0)  {
			for (j=0; j<10; j++)
				pktnr[j]=pktnrstart[j];
			sum = (int) summ;
		}

		//we want to go sure, that random in random enough
	        if (pktnr[rnd] > 0 ) {
			pktnr[rnd]--;	
			sum--;
		}
		else
			continue;

		c = sendto(fd, pkttmp[rnd], pktlength[rnd], 0, (struct sockaddr *)&sa, sizeof (sa));

		if (c > 0) {
			sentnumber++;
			sentbytes = sentbytes + 24 + pktlength[rnd];
		}

		if (sentnumber == p->count) 
			goto out;

		//exit if stop flag is pressed
		if (stop_flag == 1) {
			gdk_threads_enter ();

			gtk_widget_set_sensitive (p->button1, TRUE);
			gtk_widget_set_sensitive (p->button2, TRUE);
			gtk_widget_set_sensitive (p->button3, TRUE);
			gtk_widget_set_sensitive (p->button4, TRUE);
			gtk_widget_set_sensitive (p->button5, TRUE);
			gtk_widget_set_sensitive (p->button6, TRUE);

			snprintf(buff, 100, "  Stoped... Completed %ld cycles.  Sent %ld packets on interface: %s", li,  sentnumber, iftext);
			gtk_statusbar_push(GTK_STATUSBAR(p->button),
								GPOINTER_TO_INT(p->context_id), buff);

			//gdk_flush();
			gdk_threads_leave ();
			close(fd);
			return NULL;
		}

		while (gap3 < p->del) {

			gettimeofday(&nowstr1, NULL);
			gap3 = (nowstr1.tv_sec*1000000 + nowstr1.tv_usec) -
					(last1.tv_sec*1000000 + last1.tv_usec);
			gap4 = nowstr1.tv_sec - first.tv_sec;

			if (gap4 > seconds) {
				gdk_threads_enter ();

				snprintf(buff, 100, "   Sent %ld packets on interface: %s with rate %ld kbit/s", sentnumber, iftext, sentbytes/125);
				sentbytes=0;
				gtk_statusbar_push(GTK_STATUSBAR(p->button), 
							GPOINTER_TO_INT(p->context_id), buff);

				//gdk_flush();
				gdk_threads_leave ();

				seconds++;
			}
		}
	}
    }
			
	out:

	/* we sent all the packets, let's activate the toolbar */
	gdk_threads_enter ();

	gtk_widget_set_sensitive (p->button1, TRUE);
	gtk_widget_set_sensitive (p->button2, TRUE);
	gtk_widget_set_sensitive (p->button3, TRUE);
	gtk_widget_set_sensitive (p->button4, TRUE);
	gtk_widget_set_sensitive (p->button5, TRUE);
	gtk_widget_set_sensitive (p->button6, TRUE);

	snprintf(buff, 100, "  Completed %ld cycles. Sent %ld packets on interface: %s", li, sentnumber, iftext);
	gtk_statusbar_push(GTK_STATUSBAR(p->button), GPOINTER_TO_INT(p->context_id), buff);

	if (close(fd) != 0) {
		//printf("Warning! close(fd) returned -1!\n");
		error("Warning! close(fd) returned -1!");
	}

	//gdk_flush();
	gdk_threads_leave ();

	return NULL;

}

