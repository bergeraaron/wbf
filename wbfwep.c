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

#include <openssl/rc4.h>

//crc stuff
u_int32_t crc_tab[256];
unsigned char * icvp;
unsigned int crc;
unsigned int compcrc;

u_int32_t chksum_crc32(unsigned char *block, unsigned int length)
{
   register unsigned long crc;
   unsigned long i;

   crc = 0xFFFFFFFF;
   for (i = 0; i < length; i++)
   {
      crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
   }
   return (crc ^ 0xFFFFFFFF);
}

void chksum_crc32gentab()
{
   unsigned long crc, poly;
   int i, j;

   poly = 0xEDB88320L;
   for (i = 0; i < 256; i++)
   {
      crc = i;
      for (j = 8; j > 0; j--)
      {
	 if (crc & 1)
	 {crc = (crc >> 1) ^ poly;}
	 else
	 {crc >>= 1;}
      }
      crc_tab[i] = crc;
   }
}


bool verify_the_key(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid, unsigned char * key,unsigned int v_key_len)
{
	bool flag;
//	int n_data=0;
	unsigned long good=0;
	unsigned long bad=0;
	unsigned char full_key[16];
	unsigned int full_key_size=8;
	unsigned char * icvp;
	unsigned int crc;
	unsigned int compcrc;

	for(int y =0; y < 16; y++)
		full_key[y]=0;

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
		{
			//ok this is one of ours so lets check it out.
			full_key[0] = dataarray[y]->iv[0];//0xff
			full_key[1] = dataarray[y]->iv[1];//0xff
			full_key[2] = dataarray[y]->iv[2];//0x00			
			full_key[3] = key[0];
			full_key[4] = key[1];
			full_key[5] = key[2];
			full_key[6] = key[3];
			full_key[7] = key[4];
			if(v_key_len == 13)
			{
			full_key[8] = key[5];
			full_key[9] = key[6];
			full_key[10] = key[7];
			full_key[11] = key[8];
			full_key[12] = key[9];
			full_key[13] = key[10];
			full_key[14] = key[11];
			full_key[15] = key[12];
			full_key_size = 16;
			}

			unsigned char * un_data_section = new unsigned char[dataarray[y]->data_size];

			RC4_KEY rc4_key;
			RC4_set_key(&rc4_key, full_key_size, full_key);
			RC4(&rc4_key, dataarray[y]->data_size, dataarray[y]->encdata, un_data_section);

			//printf("IV: %02X%02X%02X %02X %02X \n",dataarray[y]->iv[0],dataarray[y]->iv[1],dataarray[y]->iv[2],dataarray[y]->encdata[0],un_data_section[0]);

			icvp = un_data_section + dataarray[y]->data_size - 4;
			crc = icvp[0] | (icvp[1] << 8) | (icvp[2] << 16) | (icvp[3] << 24);
			//printf("crc: %08X\n",crc);

			compcrc =  chksum_crc32(un_data_section, dataarray[y]->data_size-4);
		//printf("compcrc: %08X\n\n",compcrc);

			if(crc == compcrc)
			{
				if(un_data_section[0] == 0xAA && un_data_section[1] == 0xAA)//match the snap header
				{good++;}
				else
				{bad++;}
			}
			else
			bad++;

			free(un_data_section);
		}
	}
//	printf("snap verified good: %lu bad: %lu\n",good,bad);
	if(good > bad)
		return true;
	else
		return false;
}
bool verify_the_key_packet_display(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid, unsigned char * key,unsigned int v_key_len)
{
	bool flag;
//	int n_data=0;
	unsigned long good=0;
	unsigned long bad=0;
	unsigned char full_key[16];
	unsigned int full_key_size=8;
	unsigned char * icvp;
	unsigned int crc;
	unsigned int compcrc;

	for(int y =0; y < 16; y++)
		full_key[y]=0;

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
		{
			//ok this is one of ours so lets check it out.
			full_key[0] = dataarray[y]->iv[0];//0xff
			full_key[1] = dataarray[y]->iv[1];//0xff
			full_key[2] = dataarray[y]->iv[2];//0x00			
			full_key[3] = key[0];
			full_key[4] = key[1];
			full_key[5] = key[2];
			full_key[6] = key[3];
			full_key[7] = key[4];
			if(v_key_len == 13)
			{
			full_key[8] = key[5];
			full_key[9] = key[6];
			full_key[10] = key[7];
			full_key[11] = key[8];
			full_key[12] = key[9];
			full_key[13] = key[10];
			full_key[14] = key[11];
			full_key[15] = key[12];
			full_key_size = 16;
			}

			unsigned char * un_data_section = new unsigned char[dataarray[y]->data_size];

			RC4_KEY rc4_key;
			RC4_set_key(&rc4_key, full_key_size, full_key);
			RC4(&rc4_key, dataarray[y]->data_size, dataarray[y]->encdata, un_data_section);

			//printf("IV: %02X%02X%02X %02X %02X \n",dataarray[y]->iv[0],dataarray[y]->iv[1],dataarray[y]->iv[2],dataarray[y]->encdata[0],un_data_section[0]);

			icvp = un_data_section + dataarray[y]->data_size - 4;
			crc = icvp[0] | (icvp[1] << 8) | (icvp[2] << 16) | (icvp[3] << 24);
			//printf("crc: %08X\n",crc);

			compcrc =  chksum_crc32(un_data_section, dataarray[y]->data_size-4);
		//printf("compcrc: %08X\n\n",compcrc);

			if(crc == compcrc)
			{
//				printf("encoded\n");
				//print off the good packets
//				for(int x=0;x<dataarray[y]->data_size;x++)
//				{printf("%02X ",dataarray[y]->encdata[x]);}
//				printf("\ndecoded\n");
				//print off the good packets
//				for(int x=0;x<dataarray[y]->data_size;x++)
//				{printf("%02X ",un_data_section[x]);}
//				printf("\n");

				if(un_data_section[0] == 0xAA && un_data_section[1] == 0xAA)//match the snap header
				{good++;}
				else
				{bad++;}
			}
			else
			bad++;

			free(un_data_section);
		}
	}
//	printf("snap verified good: %lu bad: %lu\n",good,bad);
	if(good > bad)
		return true;
	else
		return false;
}

