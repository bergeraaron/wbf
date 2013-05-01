#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <pcap.h>
#include <iostream>
#include <signal.h>
#include <sqlite3.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>

using namespace std;

#include "main.h"
#include "wbfwep.h"
#include "wbfsqlite3.h"
#include "wbfpcap.h"

#include <openssl/rc4.h>

char errbuf[PCAP_ERRBUF_SIZE];

pcap_t *handle;
struct pcap_pkthdr header;	/* The header that pcap gives us */
u_char *packet;		/* The actual packet */
const u_char *temppacket;		// The temp packet
int i = 0;
int failed=0;
int off=0;
char time_temp[8];
int temp_jump=0;
unsigned char lbssid[6];
int tocrack;
bool prism_flag = false;
int remain_size=0;
int x=0;
unsigned char poskey[5];
unsigned char tmpkey[64];
unsigned int key_len=0;
char capture_file_name[512];

//sqlite 3 stuff
sqlite3 *db;
sqlite3_stmt *pStmt;
bool sqlite3_flag = false;
char sqlite3_db_file_name[512];
char sqlite3_qry[512];
char *zErrMsg = 0;
int rc;
  
//packet structs
int ctr=0;
int vctr=0;
int datactr=0;
SMALL_AP_BEACON_FRAME** smallAParray = NULL;
SMALL_AP_BEACON_FRAME** validAParray = NULL;
DATA_FRAME_TO_CRACK** dataframes = NULL;

//server
int serversock, clientsock;
struct sockaddr_in echoserver, echoclient;
unsigned char sckbff[256];
unsigned char sndsckbff[1024];
int amtts = 0;
int key_found=0;
int packet_len = 0;
int sa,sb,sc=0;
int temp_sa,temp_sb =0;//the slices that were completed
unsigned char pid;//max of 256 clients or processes..
unsigned char received_pid;//pid we received back from the client
unsigned char full_key_space[512][512];//this is for keeping track of the full keyspace

int we=0;
int qw=0;

//state file
FILE * sFile;
char sfilename[32];

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

void shutnicely(int sig)
{
	printf("signal caught: Shutting down\n");
		//clean up our main array for the aps
	printf("smallAParray: ctr:%d\n",ctr);
	 for(i = 0; i < ctr; i++) {
	  free(smallAParray[i]);
	  i++;
	 }
	 if(ctr > 0)
	 	free(smallAParray);

	printf("dataframes: datactr:%d\n",datactr);
	 for(i = 0; i < datactr; i++) {
	  free(dataframes[i]->encdata);
	  free(dataframes[i]);
	  i++;
	 }
	 if(datactr > 0)
	 	free(dataframes);

	 	close(clientsock);
	 	close(serversock);

		if(sqlite3_flag)
			sqlite3_close(db);

		exit(1);
}

int main(int argc, char *argv[])
{

	chksum_crc32gentab();
	
	if(argc <= 1)
	{
		printf("Usage:\n ./bruteforceserver <options>\n");
		printf("\t-----OPTIONS-----\n");
		printf("\t-c\tcapture file\n");
		printf("\t-sdb\tsqlite3 db file\n");
		return 0;
	}
	else
	{
		for(we=0;we < argc; we++)
		{
			printf("%d %s\n",we,argv[we]);
			if(strcmp(argv[we],"-c") == 0)
			{
				printf("we have a capture file\n");
				for(qw=0;qw < 512;qw++)
					capture_file_name[qw]=0;
				we++;
				sprintf(capture_file_name,"%s",argv[we]);
			}
			else if(strcmp(argv[we],"-sdb") == 0)
			{
				printf("we have a sqlite3 file\n");
				sqlite3_flag = true;
				for(qw=0;qw < 512;qw++)
					sqlite3_db_file_name[qw]=0;
				we++;
				sprintf(sqlite3_db_file_name,"%s",argv[we]);
			}
		}
	}
	for(we=0;we<=0xff;we++)
		for(qw=0;qw<=0xff;qw++)
			full_key_space[we][qw]=255;

	//catch some signals
	signal(SIGABRT, &shutnicely);
	signal(SIGTERM, &shutnicely);
	signal(SIGINT, &shutnicely);
	
	
	if(sqlite3_flag)
	{
	  printf("attempt to open the db\n");
	//lets open the db
	  //rc = sqlite3_open("wireless.dbl", &db);
	  rc = sqlite3_open(sqlite3_db_file_name, &db);
	  printf("rc: %d\n",rc);
	  if( rc ){
	    printf("Can't open database: %s\n", sqlite3_errmsg(db));
	    sqlite3_close(db);
	    exit(1);
	  }
	  printf("db opened\n");
	}

	//server part
  /* Create the TCP socket */
  if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    printf("failed\n");
    return 1;
  }
	int on = 1;
	int status = 0;
	//socket options
  status = setsockopt(serversock, SOL_SOCKET,SO_REUSEADDR,(const char *) &on, sizeof(on));


  /* Construct the server sockaddr_in structure */
  memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
  echoserver.sin_family = AF_INET;                  /* Internet/IP */
  echoserver.sin_addr.s_addr = htonl(INADDR_ANY);   /* Incoming addr */
  echoserver.sin_port = htons(atoi("9999"));       /* server port */

	handle = pcap_open_offline(capture_file_name, errbuf);
	if (handle == NULL) {
	 fprintf(stderr, "Couldn't open file %s\n", errbuf);
	 return(2);
	}
	//file open, so lets loop through it
  while(1)
  {
  	off=0;
					
    if((temppacket = pcap_next(handle, &header)) == NULL)
      break;

//printf("Jacked a packet with length of [%d]\n", header.len);

		if(prism_flag)
		{
			if(header.len > 144)//this removes the prism header...
			{
				x=0;
				remain_size = header.len - 144;
				printf("remaining size: %d\n",remain_size);
				packet = new u_char[remain_size];
				for(int k=0;k<remain_size;k++)
				{
					x = k + 144;
					packet[k] = temppacket[x];
				}
				printf("\n");
				header.len = remain_size;
			}
			else
				header.len = 0;
		}
		else
		{
			packet = new u_char[header.len];
			for(int k=0;k<header.len;k++)
				packet[k] = temppacket[k];
		}

		// Print its length
		//printf("Jacked a packet with length of [%d]\n", header.len);
		//0x08 data packet
		//0x50 probe response
		//0x80 beacon
		packet_len = header.len;
if(packet_len > 0)
{
		if(packet[0x00] == 0x80)//beacon
		{
			if(packet[0x24] == 0x00)
			{
					for(i=0;i < 6; i++)
						lbssid[i] = (unsigned char)packet[16+i];

				if(check_bssid(smallAParray,ctr,lbssid))
				{
					//woohoo dynamic allocation
					smallAParray = (struct SMALL_AP_BEACON_FRAME **)realloc(smallAParray, (ctr + 1) * sizeof(struct SMALL_AP_BEACON_FRAME *));
				  // allocate memory for one struct
				  smallAParray[ctr] = (struct SMALL_AP_BEACON_FRAME *)malloc(sizeof(struct SMALL_AP_BEACON_FRAME));
					
					off++;//frame_type
					off++;//frame_flag
					off = off + 2;//duration
					off = off + 6;//dest_addr
					off = off + 6;//src_addr

					for(i=0;i < 6; i++)
						smallAParray[ctr]->bssid[i] = (unsigned char)packet[off++];

					off = off + 2;//frag_seq
					//wireless management frame 12 bytes
					off = off + 8;//time_temp
					off = off + 2;//beacon_interval
					smallAParray[ctr]->cap_info = (packet[off+1] << 8) | packet[off+0];
					off = off + 2;
	
					if(CHECK_BIT(smallAParray[ctr]->cap_info,4))//check wep
						smallAParray[ctr]->wep_flag=1;
					else
						smallAParray[ctr]->wep_flag=0;

					//printf("off: %d len: %d \n",off,header.len);

					//tagged parameters set
					while(off < header.len)
					{
						//printf("s off %d headlen %d \n",off,header.len);
						if(packet[off] == 0x00)
						{
							//printf("ssid\n");
							//ssid
							off++;//jumping the ssid tag
							smallAParray[ctr]->ssid_len = packet[off++];
							for(i=0;i < smallAParray[ctr]->ssid_len; i++)
								smallAParray[ctr]->ssid_name[i] = (unsigned char)packet[off++];
								smallAParray[ctr]->ssid_name[i]=0;
						}
						else if(packet[off] == 0xDD)
						{
							//printf("vendor specific\n");
							off++;//jump tag
							int vndr_size = packet[off++];
							//printf("size %d\n",vndr_size);
							if(vndr_size == 26 || vndr_size == 24 || vndr_size == 22 || vndr_size == 28)
							{
								//printf("possible wpa\n");
								int wpa_check = (packet[off+0] << 32) | (packet[off+1] << 16) | (packet[off+2] << 8) | packet[off+3];
								if(wpa_check == 0x0050F201)
								{
									smallAParray[ctr]-> wpa_flag = 1;
									smallAParray[ctr]-> wep_flag = 0;
								}
								off = off + vndr_size;
							}
							else
							{
								off = off + vndr_size;
							}
						}
						else
						{
							//this gets rid of the crap I don't care about
							off++;//jump tag
							temp_jump = packet[off++];
							off = off + temp_jump;
						}
					}
				ctr++;
				}
			}
		}
		else if(packet[0x00] == 0x50)
		{
//				printf("probe response\n");

			unsigned char pr_dest_addr[6];
			unsigned char pr_src_addr[6];
			unsigned char pr_bssid[6];
			unsigned short pr_cap_info;
			unsigned char pr_ap_flag;
			unsigned char pr_wep_flag;
			unsigned char pr_wpa_flag;
			int pr_ssid_len;
			char pr_ssid_name[33];//max 32, but null termination
			char pr_channel;
			int pr_vndr_size;
			unsigned char pr_vndr[32];
			int pr_ckip_size;
			unsigned char * pr_ckip;
			int place_in_array = 0;
			bool junk_packet = false;
			int temp=0;


			off++;//frame_type
			off++;//frame_flag
			off = off + 2;//duration
			for(i=0;i < 6; i++)
			{
				pr_dest_addr[i] = (unsigned char)packet[off++];
				if(pr_dest_addr[i] != 0xFF)
				{
					junk_packet = true;
				}
			}
			for(i=0;i < 6; i++)
				pr_src_addr[i] = (unsigned char)packet[off++];
			for(i=0;i < 6; i++)
				pr_bssid[i] = (unsigned char)packet[off++];

			//source is the aps mac

				off = off + 2;//frag_seq
				//wireless management frame 12 bytes
				off = off + 8;//time_temp
				off = off + 2;//beacon_interval
				pr_cap_info = (packet[off+1] << 8) | packet[off+0];
				off = off + 2;
				if(CHECK_BIT(pr_cap_info,4))//check wep
					pr_wep_flag=1;
				else
					pr_wep_flag=0;

					while(off < header.len)
					{
						//printf("s off %d headlen %d \n",off,header.len);
						if(packet[off] == 0x00)
						{
							//printf("ssid\n");
							//ssid
							off++;//jumping the ssid tag
							pr_ssid_len = packet[off++];
							if(pr_ssid_len == 0)
								{
									junk_packet = true;
									break;
								}
							
							if(pr_ssid_len > 32)
							{
									pr_ssid_len = 0;
									junk_packet = true;
									break;
							}
							
							//check the length to see if its off the deep end
							temp = packet_len - off;//this is the remainer
					//		printf("vndr_size:%02X temp:%02X off:%02X\n",vndr_size,temp,off);
							if(pr_ssid_len > temp)
							{
								junk_packet = true;
								break;
							}

							for(i=0;i < pr_ssid_len; i++)
								pr_ssid_name[i] = (unsigned char)packet[off++];
								pr_ssid_name[i]=0;
								//have_a_ssid
								
						}
						else if(packet[off] == 0xDD)
						{
							//printf("vendor specific\n");
							off++;//jump tag
							int pr_vndr_size = packet[off++];
							if(pr_vndr_size == 0)
							{
								junk_packet = true;
								break;
							}
							//printf("size %d\n",vndr_size);
							if(pr_vndr_size == 28 || pr_vndr_size == 26 || pr_vndr_size == 24 || pr_vndr_size == 22)
							{
							//	printf("possible wpa\n");
								int pr_wpa_check = (packet[off+0] << 32) | (packet[off+1] << 16) | (packet[off+2] << 8) | packet[off+3];
								if(pr_wpa_check == 0x0050F201)
								{
									pr_wpa_flag = 1;
									pr_wep_flag = 0;
								}
								off = off + pr_vndr_size;
							}
							else
							{
								//check if its too big
								temp = packet_len - off;//this is the remainer
								//printf("vndr_size:%02X temp:%02X off:%02X\n",vndr_size,temp,off);
								if(pr_vndr_size > temp)
								{
									//we are trying to go farther than we can
									//printf("extra junk packet\n");
									junk_packet = true;
									break;
								}
								else
									off = off + pr_vndr_size;
							}
						}
						else
						{
							//this gets rid of the crap I don't care about
							off++;//jump tag
							temp_jump = packet[off++];
							temp = packet_len - off;//this is the remainer
							//printf("temp_jump:%02X temp:%02X off:%02X\n",temp_jump,temp,off);
							if(temp_jump > temp)
							{
								//we are trying to go farther than we can
								//printf("extra junk packet\n");
								junk_packet = true;
								break;
							}
							else
								off = off + temp_jump;
						}
					}

					//check against our know list
					place_in_array = return_bssid_place(smallAParray,ctr,pr_bssid);
					if(place_in_array >= 0 && pr_ssid_len > 1)
					{
						//pr_ssid_name
						if(strcmp(smallAParray[place_in_array]->ssid_name,pr_ssid_name) != 0)
						{
						//	printf("***the names are different, so we should use it***\n");
							for(int h=0;h < 33;h++)
								smallAParray[place_in_array]->ssid_name[h]=0;
							sprintf(smallAParray[place_in_array]->ssid_name,"%s",pr_ssid_name);
							smallAParray[place_in_array]->ssid_name[32]=0;
						
						printf("%03d %02X:%02X:%02X:%02X:%02X:%02X ",place_in_array,smallAParray[place_in_array]->bssid[0],smallAParray[place_in_array]->bssid[1],smallAParray[place_in_array]->bssid[2],smallAParray[place_in_array]->bssid[3],smallAParray[place_in_array]->bssid[4],smallAParray[place_in_array]->bssid[5]);
						
						printf("%32s ",smallAParray[place_in_array]->ssid_name);
						
						if(smallAParray[place_in_array]->wep_flag == 1)
							printf("WEP ");
						else if(smallAParray[place_in_array]->wpa_flag == 1)
							printf("WPA ");
						else
							printf("--- ");
						
							printf("\n");
						}
					}//end of place in array
		}//end of probe response
		else if(packet[0x00] == 0x08)
		{

			//need to check to make sure its encrypted
			off++;//frame_type
			unsigned char frame_flag = packet[off++];
			unsigned int temp_offset = off;
			unsigned char tmpbssid[6];
			int good_packet = 0;

			off = off + 2;//duration
			//arrggg need to parse out the flag so when know if the data is coming or going
			if(CHECK_BIT(frame_flag,1))//check ap
			{
				off = off + 6;//dest_addr
				for(i=0;i < 6; i++)
					tmpbssid[i] = (unsigned char)packet[off++];
			}
			else
			{
				for(i=0;i < 6; i++)
					tmpbssid[i] = (unsigned char)packet[off++];
				off = off + 6;//dest_addr
			}
			printf("%02X:%02X:%02X:%02X:%02X:%02X \n",tmpbssid[0],tmpbssid[1],tmpbssid[2],tmpbssid[3],tmpbssid[4],tmpbssid[5]);

			good_packet = check_ssid_enc_sqlite3(db,tmpbssid);

			off = temp_offset;

			if(CHECK_BIT(frame_flag,6) && good_packet > 0)//check if protected
			{
					//printf("data packet\n");
					//woohoo dynamic allocation
					dataframes = (struct DATA_FRAME_TO_CRACK **)realloc(dataframes, (datactr + 1) * sizeof(struct DATA_FRAME_TO_CRACK *));
				  // allocate memory for one struct
				  dataframes[datactr] = (struct DATA_FRAME_TO_CRACK *)malloc(sizeof(struct DATA_FRAME_TO_CRACK));

					off = off + 2;//duration
					//arrggg need to parse out the flag so when know if the data is coming or going
					if(CHECK_BIT(frame_flag,1))//check ap
					{
						off = off + 6;//dest_addr
						for(i=0;i < 6; i++)
							dataframes[datactr]->bssid[i] = (unsigned char)packet[off++];
						
					}
					else
					{
						for(i=0;i < 6; i++)
							dataframes[datactr]->bssid[i] = (unsigned char)packet[off++];
						off = off + 6;//dest_addr
					}
					//printf("%02X:%02X:%02X:%02X:%02X:%02X \n",dataframes[datactr]->bssid[0],dataframes[datactr]->bssid[1],dataframes[datactr]->bssid[2],dataframes[datactr]->bssid[3],dataframes[datactr]->bssid[4],dataframes[datactr]->bssid[5]);

					off = off + 6;//src_addr
					off = off + 2;//frag_seq

					for(i=0;i<3;i++)
						dataframes[datactr]->iv[i] = (unsigned char)packet[off++];

					//printf("IV: %02X %02X %02X\n",dataframes[datactr]->iv[0],dataframes[datactr]->iv[1],dataframes[datactr]->iv[2]);

					unsigned char key_index = (unsigned char)packet[off++];

					dataframes[datactr]->data_size = (header.len) - off; 
					
					//printf("data_size: %d\n",dataframes[datactr]->data_size);

					if(dataframes[datactr]->data_size > 0)
					{
						dataframes[datactr]->encdata = new unsigned char[dataframes[datactr]->data_size];
	
						for(i = 0;i < dataframes[datactr]->data_size; i ++)
						{
							dataframes[datactr]->encdata[i] = (unsigned char)packet[off+i];
						}

						datactr++;
					}

			}//end check protected
		}//end of data packet
}
	free(packet);		
	}
	// And close the session
	pcap_close(handle);
/*
	//done with the packets
	for(int k =0;k < ctr;k++)
	{
		if(smallAParray[k]->wep_flag == 1)//only want wep
		{
			smallAParray[k]->datanum = check_for_data(dataframes, datactr, smallAParray[k]->bssid);
			if(smallAParray[k]->datanum > 1)//only want some data
			{
				

				//unit with data and wep
				validAParray = (struct SMALL_AP_BEACON_FRAME **)realloc(validAParray, (ctr + 1) * sizeof(struct SMALL_AP_BEACON_FRAME *));
				// allocate memory for one struct
				validAParray[vctr] = (struct SMALL_AP_BEACON_FRAME *)malloc(sizeof(struct SMALL_AP_BEACON_FRAME));
				validAParray[vctr] = smallAParray[k];
				vctr++;

			}
		}
	}
*/


	exit(0);
	return 0;
}


