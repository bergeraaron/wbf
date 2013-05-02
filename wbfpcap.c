#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <pcap.h>
#include <iostream>
#include <signal.h>

using namespace std;

#include "main.h"
#include "wbfpcap.h"

extern SMALL_AP_BEACON_FRAME** smallAParray;
extern DATA_FRAME_TO_CRACK** dataframes;

bool check_bssid(SMALL_AP_BEACON_FRAME** LAParray, int lctr,unsigned char * local_bssid)
{
	bool flag;

	if(lctr == 0)
		return true;
	
	for(int y=0;y < lctr;y++)
	{
		//printf("%02X:%02X:%02X:%02X:%02X:%02X ",LAParray[y]->bssid[0],LAParray[y]->bssid[1],LAParray[y]->bssid[2],LAParray[y]->bssid[3],LAParray[y]->bssid[4],LAParray[y]->bssid[5]);
		//printf("%02X:%02X:%02X:%02X:%02X:%02X \n",local_bssid[0],local_bssid[1],local_bssid[2],local_bssid[3],local_bssid[4],local_bssid[5]);
		
		for(int k=0;k<6;k++)
		{
			if(LAParray[y]->bssid[k] == local_bssid[k])
				flag = true;
			else
				flag = false;
		}
		if(flag == true)//we already have it
			return false;
	}
	return true;

}

int return_bssid_place(SMALL_AP_BEACON_FRAME** LAParray, int lctr,unsigned char * local_bssid)//function returns where it is in the array
{
	bool flag;

	if(lctr == 0)
		return -1;
	
	for(int y=0;y < lctr;y++)
	{
		for(int k=0;k<6;k++)
		{
			if(LAParray[y]->bssid[k] == local_bssid[k])
				flag = true;
			else
				flag = false;
		}
		if(flag == true)//we already have it
			return y;
	}
	return -1;

}

unsigned int check_for_data(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid)
{
	bool flag;
	int n_data=0;
	
	if(dctr == 0)
		return 0;
	
	for(int y=0;y < dctr;y++)
	{
		for(int k=0;k<6;k++)
		{
			if(dataarray[y]->bssid[k] == local_bssid[k])
				flag = true;
			else
				flag = false;
		}
		if(flag == true)//we already have it
			n_data++;
	}
	return n_data;

}

unsigned int get_smallest_data_size(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid)
{
	int smallest_size_packet = 0;
	int data_size=65535;
	bool flag = false;
	
	if(dctr == 0)
		return 0;
	
	for(int y=0;y < dctr;y++)
	{
		for(int k=0;k<6;k++)
		{
			if(dataarray[y]->bssid[k] == local_bssid[k])
				flag = true;
			else
				flag = false;
		}
		if(flag)
		{
			if(dataarray[y]->data_size < data_size)
			{
				data_size = dataarray[y]->data_size;
				smallest_size_packet = y;
			}
		}

	}
	return smallest_size_packet;
}



unsigned int get_smallest_data_size_ignore_iv(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid,unsigned char iv1,unsigned char iv2,unsigned char iv3)
{
/*
sndsckbff[2] = dataframes[packet_to_crack]->iv[0];//iv1
sndsckbff[3] = dataframes[packet_to_crack]->iv[1];//iv2
sndsckbff[4] = dataframes[packet_to_crack]->iv[2];//iv3
*/
	int smallest_size_packet = 0;
	int data_size=65535;
	bool flag = false;
	
	if(dctr == 0)
		return 0;
	
	for(int y=0;y < dctr;y++)
	{
		if(dataarray[y]->iv[0] != iv1 && dataarray[y]->iv[1] != iv2 && dataarray[y]->iv[2] != iv3)
		{
			for(int k=0;k<6;k++)
			{
				if(dataarray[y]->bssid[k] == local_bssid[k])
					flag = true;
				else
					flag = false;
			}
			if(flag)
			{
				if(dataarray[y]->data_size < data_size)
				{
					data_size = dataarray[y]->data_size;
					smallest_size_packet = y;
				}
			}
		}
	}
	return smallest_size_packet;
}


bool load_pcap_from_file(char * filename,char * errbuf,bool prism_flag,int & datactr,int & ctr)//,SMALL_AP_BEACON_FRAME& smallAParray,DATA_FRAME_TO_CRACK& dataframes
{
	int i,x=0;
//	int ctr=0;
	int packet_len = 0;
	int off=0;
	int remain_size=0;
	int temp_jump=0;
	unsigned char lbssid[6];
	pcap_t *handle;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	u_char *packet;		/* The actual packet */
	const u_char *temppacket;		// The temp packet

	handle = pcap_open_offline(filename, errbuf);
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
								if(wpa_check == 0x0050F204)//WPS
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
			
			if(CHECK_BIT(frame_flag,6))//check wep
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

//done with the file
printf("ctr:%d datactr:%d\n",ctr,datactr);

printf("done with the file\n");

return true;
}


