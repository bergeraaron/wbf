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


#if defined(CURSES)
#include "wbfncurses.h"
#endif

char errbuf[PCAP_ERRBUF_SIZE];

pcap_t *handle;
struct pcap_pkthdr header;	/* The header that pcap gives us */
u_char *packet;			/* The actual packet */
const u_char *temppacket;	// The temp packet
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
char crack_ssid[33];

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

		#if defined(CURSES)
		endwin();
		#endif

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

    load_pcap_from_file(capture_file_name,errbuf,prism_flag,datactr,ctr);//,smallAParray,dataframes

    printf("datactr: %d ctr: %d\n",datactr,ctr);

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

	//printf("------------------------------------------------------------------------------------------------------\n");
	printf("data frames: %d\n",datactr);
	printf("total number of Valid APs: %d\n",vctr);

	printf("   %16s %32s %4s %4s \n","BSSID","SSID","ENC","data");

	for(int k =0;k < vctr;k++)
	{
		printf("%03d %02X:%02X:%02X:%02X:%02X:%02X ",k,validAParray[k]->bssid[0],validAParray[k]->bssid[1],validAParray[k]->bssid[2],validAParray[k]->bssid[3],validAParray[k]->bssid[4],validAParray[k]->bssid[5]);
		printf("%32s ",validAParray[k]->ssid_name);
		
		if(validAParray[k]->wep_flag == 1)
			printf("WEP ");
		else if(validAParray[k]->wpa_flag == 1)
			printf("WPA ");
		else
			printf("--- ");
			
			printf("%02d\n",validAParray[k]->datanum);
	}//end of looking through the basestations

	printf("Please enter the number of the network(-1 to exit): ");
	cin >> tocrack;
	if(tocrack < 0)
	{
		//free up the ram for the data frames
		exit(1);
	}
	else
	{
		printf("time to find the smallest packet\n");
		int packet_to_crack = get_smallest_data_size(dataframes, datactr, validAParray[tocrack]->bssid);
		printf("packet to crack %d \n",packet_to_crack);
		printf("%03d %02X:%02X:%02X:%02X:%02X:%02X ",tocrack,validAParray[tocrack]->bssid[0],validAParray[tocrack]->bssid[1],validAParray[tocrack]->bssid[2],validAParray[tocrack]->bssid[3],validAParray[tocrack]->bssid[4],validAParray[tocrack]->bssid[5]);

		if(sqlite3_flag)
		{
			
			unsigned char testedkey[32];
			for(int t=0;t<32;t++)
				testedkey[t]=0;
		
			bool returned = check_key_sqlite3(db,dataframes[packet_to_crack]->bssid,testedkey,datactr,dataframes);
			if(returned == true)
			{
				printf("we found one\n");
				key_found = 1;
				amtts=0;
				return 0;
			}
		}
		else
		{
			//we should check to see if we have a key
			sprintf(sfilename,"key/%02X:%02X:%02X:%02X:%02X:%02X.key",dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5]);
			printf("filename: %s\n",sfilename);
			sFile = fopen(sfilename,"r");
			if(sFile!= NULL)
			{
				printf("we have a key file\n");
				key_found = 1;
				fclose(sFile);
				return 0;
			}
		}

		//check to see if we have a state already	
		sprintf(sfilename,"state/%02X:%02X:%02X:%02X:%02X:%02X.state",dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5]);
		printf("filename: %s\n",sfilename);
		sFile = fopen(sfilename,"r");
		if(sFile!= NULL)
		{
			printf("we have a file\n");
			//fscanf(sFile, "%X\n%X\n%X\n",sa,sb,sc);
			fscanf(sFile, "%X",&sa);
			fscanf(sFile, "%X",&sb);
			fscanf(sFile, "%X",&sc);
			printf("we have a state file sa:%d sb:%d sc:%d\n",sa,sb,sc);
			fclose(sFile);

			//set our array as being good up to there
			//two part it
			//everything up to sa done
			
			for(we=0;we < sa;we++)
				for(qw=0;qw<=0xff;qw++)
					full_key_space[we][qw]=0;

				for(qw=0;qw<=sb;qw++)
					full_key_space[sa][qw]=0;

		}
		for(i = 0; i < 33; i++)
		{
			crack_ssid[i] = validAParray[tocrack]->ssid_name[i];
		}
		
		//we will no longer use the ap stuff so we should be able to clear it out.
		//free up the ram for the aps
		 for(i = 0; i < ctr; i++) {
		  free(smallAParray[i]);
		  i++;
		 }
		 if(ctr > 0)
		 free(smallAParray);
		 ctr=0;//set to 0 so if we ctl-C we won't try to free it again

		//socket stuff
    // Bind the server socket
    if (bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
	#ifndef CURSES
	printf("Failed to bind the server socket\n");
	#endif
	//free up the ram for the data frames
	exit(1);
    }
    // Listen on the server socket
    if (listen(serversock, 5) < 0) {
	#ifndef CURSES
	printf("Failed to listen on server socket\n");
	#endif
      	exit(1);
    }
		// Run until cancelled
		while (1) 
		{
//spammy		
			#if defined(CURSES)
		        int row,col=0;
       			scr_init(&row,&col);
		        printtemplate(row,col);
		        refresh();
			//print the ssid
			printssid(crack_ssid);
			char temp_bssid[64];
			for(i=0;i<64;i++)
			{temp_bssid[i]=0;}
			sprintf(temp_bssid,"%02X:%02X:%02X:%02X:%02X:%02X",dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5]);
			printbssid(temp_bssid);
			#endif

			
			//lets open a file to store the state
			sprintf(sfilename,"state/%02X:%02X:%02X:%02X:%02X:%02X.state",dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5]);
			sFile = fopen (sfilename,"w");
			fprintf (sFile, "%02X\n%02X\n%02X\n",sa,sb,sc);
			fclose (sFile);
			
			if(failed == 1)
			{
				close(clientsock);
				close(serversock);
		    // Bind the server socket
		    if (bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
			#ifndef CURSES
			printf("Failed to bind the server socket\n");
			#endif		
			sleep(30);
				}
		    else
		    	failed = 0;	
		    // Listen on the server socket
		    if (listen(serversock, 5) < 0) {
			#ifndef CURSES
			printf("Failed to listen on server socket\n");
			#endif
			sleep(30);
		    }
		    else
					failed = 0;				
			}

			#if defined(CURSES)
			char temp[32];
			sprintf(temp,"%02X %02X %02X %02X %02X",sa,sb,0x00,0x00,0x00);
			printcks(temp);
			#else
			printf("%03d %02X:%02X:%02X:%02X:%02X:%02X ",tocrack,dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5]);
			printf("Next Key Space: %02X %02X %02X %02X %02X \n",sa,sb,0x00,0x00,0x00);
			#endif
			//printf("waiting for a client to connect...\n");
		  unsigned int clientlen = sizeof(echoclient);
		  // Wait for client connection
		  if ((clientsock = accept(serversock, (struct sockaddr *) &echoclient, &clientlen)) < 0) 
		  {
			#ifndef CURSES
			printf("Failed to accept client connection\n");
			#endif
			close(clientsock);
			failed=1;
		  }
		  else
		  {
			#ifndef CURSES
		  fprintf(stdout, "Client connected: %s\n", inet_ntoa(echoclient.sin_addr));
			#endif
		  }
		  //handle the client
			
      int received = -1;
      // Receive message
      if ((received = recv(clientsock, sckbff, 256, 0)) < 0) {
	#ifndef CURSES
        printf("Failed to receive initial bytes from client\n");
	#endif
        close(clientsock);
        failed=1;
      }
      //printf("read %d bytes\n",received);
      //send back the info
      if (received > 0) 
      {
if(key_found == 1)
{
	//we have found the key
		sndsckbff[0]=0x08;
		amtts=1;
}
else
{

      	//parse through to see what packet we got
      	if(sckbff[0] == 1)//starting condition for a client
      	{
	#ifndef CURSES
		printf("sa: %02X sb: %02X \n",sa,sb);
	#endif
		if(sa > 0xFF)
		{
	#ifndef CURSES
			printf("error: ran out of keyspace\n");
	#endif
			//check if we have stuff still checked out.
			amtts = 0;
			for(we=0;we<=0xFF;we++)
			{
				for(qw=0;qw<=0xFF;qw++)
				{
					if(full_key_space[we][qw] != 0)//checked out..
					{
	#ifndef CURSES
						printf("just check it out again\n");
				      		printf("client first connected\n");
	#endif
						pid++;
				      		//it is a client connecting
				      		sndsckbff[0] = 0x02;//we are sending data to the client
				      		sndsckbff[1] = pid;//we are sending data to the client
				      		sndsckbff[2] = dataframes[packet_to_crack]->iv[0];//iv1
				      		sndsckbff[3] = dataframes[packet_to_crack]->iv[1];//iv2
				      		sndsckbff[4] = dataframes[packet_to_crack]->iv[2];//iv3
				      		//section to try
				      		sndsckbff[5] = we;//a
				      		sndsckbff[6] = qw;//b
				      		sndsckbff[7] = sc;//c
	#ifndef CURSES
			      			printf("data size: %08X\n",dataframes[packet_to_crack]->data_size);
	#endif
								      		
				      		//size of data packet
				      		sndsckbff[8] = dataframes[packet_to_crack]->data_size & 0xFF;//top
				      		sndsckbff[9] = (dataframes[packet_to_crack]->data_size>> 8) & 0xFF;//bottom
								      		
				      		amtts = 10 + dataframes[packet_to_crack]->data_size;
				      		for(int k = 0; k < dataframes[packet_to_crack]->data_size; k++)
				      		{sndsckbff[10+k] = dataframes[packet_to_crack]->encdata[k];}

				      		//set the keyspace as being checked out to the current/new pid
				      		full_key_space[we][qw]=pid;
		   				break;
					}//endif
					if(amtts > 0)
						break;
				}//endforloop
					if(amtts > 0)
					break;
			}//endforloop
		}//endif
		else
		{
			pid++;
	#ifndef CURSES
			printf("client first connected\n");
	#endif
	     		//it is a client connecting
	      		sndsckbff[0] = 0x02;//we are sending data to the client
	      		sndsckbff[1] = pid;//we are sending data to the client
	      		sndsckbff[2] = dataframes[packet_to_crack]->iv[0];//iv1
	      		sndsckbff[3] = dataframes[packet_to_crack]->iv[1];//iv2
	      		sndsckbff[4] = dataframes[packet_to_crack]->iv[2];//iv3
	      		//section to try
	      		sndsckbff[5] = sa;//a
	      		sndsckbff[6] = sb;//b
	      		sndsckbff[7] = sc;//c
	#ifndef CURSES
	      		printf("data size: %08X as int:%d\n",dataframes[packet_to_crack]->data_size,dataframes[packet_to_crack]->data_size);
	#endif		      		
	      		//size of data packet
	      		sndsckbff[8] = dataframes[packet_to_crack]->data_size & 0xFF;//top
	      		sndsckbff[9] = (dataframes[packet_to_crack]->data_size>> 8) & 0xFF;//bottom
				      		
	      		amtts = 10 + dataframes[packet_to_crack]->data_size;
	      		for(int k = 0; k < dataframes[packet_to_crack]->data_size; k++)
	      		{sndsckbff[10+k] = dataframes[packet_to_crack]->encdata[k];}
	
	      		//set the keyspace as being checked out to the current/new pid
	      		full_key_space[sa][sb]=pid;
	      		
			sc=0x00;
			sb++;
			if(sb > 0xFF)
			{
				sb=0x00;
				sa++;
			}
		}//endelse
      	}
      	else if(sckbff[0] == 0x03)
      	{
      		//printf("client done with its packet, but no key found\n");
		received_pid = sckbff[1];//pid from client
		temp_sa = sckbff[2];//the slices that were completed
		temp_sb = sckbff[3];//the slices that were completed
		full_key_space[temp_sa][temp_sb] = 0;//cleared nothing found
	        #if defined(CURSES)
                char temp[32];
        	sprintf(temp,"%02X %02X %02X %02X %02X",temp_sa,temp_sb,0x00,0x00,0x00);
               	printltk(temp);
               	#else
		printf("temp_sa: %02X temp_sb: %02X \n",temp_sa,temp_sb);
		printf("sa: %02X sb: %02X \n",sa,sb);
		#endif
		if(sa > 0xFF)
		{
	#ifndef CURSES
			printf("error: ran out of keyspace\n");
			printf("check if we have stuff still checked out\n");
	#endif					
			amtts = 0;
			for(we=0;we<=0xFF;we++)
			{
				for(qw=0;qw<=0xFF;qw++)
				{
					if(full_key_space[we][qw] != 0)//checked out..
					{
	#ifndef CURSES
						printf("we: %02X qw: %02X \n",we,qw);
						printf("just check it out again...\n");
	#endif
						pid++;
				      		//it is a client connecting
				      		sndsckbff[0] = 0x02;//we are sending data to the client
				      		sndsckbff[1] = received_pid;//we are sending data to the client
				      		sndsckbff[2] = dataframes[packet_to_crack]->iv[0];//iv1
				      		sndsckbff[3] = dataframes[packet_to_crack]->iv[1];//iv2
				      		sndsckbff[4] = dataframes[packet_to_crack]->iv[2];//iv3
				      		//section to try
				      		sndsckbff[5] = we;//a
				      		sndsckbff[6] = qw;//b
				      		sndsckbff[7] = sc;//c
				      		//printf("data size: %08X\n",dataframes[packet_to_crack]->data_size);
									      		
				      		//size of data packet
				      		sndsckbff[8] = dataframes[packet_to_crack]->data_size & 0xFF;//top
				      		sndsckbff[9] = (dataframes[packet_to_crack]->data_size>> 8) & 0xFF;//bottom
				      		amtts = 10 + dataframes[packet_to_crack]->data_size;
				      		for(int k = 0; k < dataframes[packet_to_crack]->data_size; k++)
				      		{sndsckbff[10+k] = dataframes[packet_to_crack]->encdata[k];}
				      		//set the keyspace as being checked out to the current/new pid
				      		full_key_space[we][qw]=received_pid;
		   				break;
					}
						if(amtts > 0)
						break;
				}
					if(amtts > 0)
					break;
			}
			if(amtts == 0)
			{
				printf("really out of keyspace\n");
				exit(1);
			}
		}
		else
		{	
	      		//it is a client connecting
	      		sndsckbff[0] = 0x02;//we are sending data to the client
	      		sndsckbff[1] = received_pid;//we are sending data to the client
	      		sndsckbff[2] = dataframes[packet_to_crack]->iv[0];//iv1
	      		sndsckbff[3] = dataframes[packet_to_crack]->iv[1];//iv2
	      		sndsckbff[4] = dataframes[packet_to_crack]->iv[2];//iv3
	      		//section to try
	      		sndsckbff[5] = sa;//a
	      		sndsckbff[6] = sb;//b
	      		sndsckbff[7] = sc;//c
	      		//printf("data size: %08X\n",dataframes[packet_to_crack]->data_size);
	
	      		//size of data packet
	      		sndsckbff[8] = dataframes[packet_to_crack]->data_size & 0xFF;//top
	      		sndsckbff[9] = (dataframes[packet_to_crack]->data_size>> 8) & 0xFF;//bottom
				      		
	      		amtts = 10 + dataframes[packet_to_crack]->data_size;
	      		for(int k = 0; k < dataframes[packet_to_crack]->data_size; k++)
	      		{sndsckbff[10+k] = dataframes[packet_to_crack]->encdata[k];}
	
	      		//set the keyspace as being checked out to the current/new pid
	      		full_key_space[sa][sb] = received_pid;
	
			sc=0x00;
			sb++;
			if(sb > 0xFF)
			{
				sb=0x00;
				sa++;
			}
		}
      	}
      	else if(sckbff[0] == 0x04)
      	{
		sndsckbff[0]=0x05;
		amtts=1;
		send(clientsock, sndsckbff, amtts, 0);

		#if defined(CURSES)
		printstat("POSSIBLE KEY");
		#else
      		printf("possible key!\n");
      		for(int i =1;i< received;i++)
      		{
      			printf("%02X",sckbff[i]);
      			poskey[i-1] = sckbff[i];
      		}
      		printf("\n\n");
      		#endif

      		//need a function to check the next data and make sure we are ok.
      		bool areweok = verify_the_key(dataframes, datactr,dataframes[packet_to_crack]->bssid,poskey,5);
	      	//areweok = false;	
		if(areweok)
      		{
			#if defined(CURSES)
			printstat("VALID KEY");
			#else
			printf("key is valid!\n");
			#endif
			key_found = 1;
			amtts=0;
			if(sqlite3_flag)
				insert_key_sqlite3(db,dataframes[packet_to_crack]->bssid,poskey);
			//lets save the key to a file :)
			FILE * pFile;
			char filename[32];
			sprintf(filename,"key/%02X:%02X:%02X:%02X:%02X:%02X.key",dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5]);
			pFile = fopen (filename,"w");
			fprintf (pFile, "%02X%02X%02X%02X%02X\n",poskey[0],poskey[1],poskey[2],poskey[3],poskey[4]);
			fclose (pFile);
      		}
      		else
      		{
      			//false so continue
			#if defined(CURSES)
			printstat("FALSE KEY");
			#else
      			printf("false so continue!\n");
			#endif
			//going to save the false keys
			FILE * pFile;
			pFile = fopen ("falsekeys.key","a");
			fprintf (pFile, "%02X:%02X:%02X:%02X:%02X:%02X %02X%02X%02X %02X%02X%02X%02X%02X\n",dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5],dataframes[packet_to_crack]->iv[0],dataframes[packet_to_crack]->iv[1],dataframes[packet_to_crack]->iv[2],poskey[0],poskey[1],poskey[2],poskey[3],poskey[4]);
			fclose (pFile);
      			amtts=0;
      		}
      	}
      	else if(sckbff[0] == 0x09 || sckbff[0] == '9')//or an ascii 9
      	{
      		//stat poll
      		for(int y=0;y<256;y++)
      			sndsckbff[y]=0;

		unsigned char * tempptr;
		tempptr = &sndsckbff[0];
		sprintf((char *)tempptr,"BSSID");
		tempptr = &sndsckbff[20];
		sprintf((char *)tempptr,"%02X:%02X:%02X:%02X:%02X:%02X",dataframes[packet_to_crack]->bssid[0],dataframes[packet_to_crack]->bssid[1],dataframes[packet_to_crack]->bssid[2],dataframes[packet_to_crack]->bssid[3],dataframes[packet_to_crack]->bssid[4],dataframes[packet_to_crack]->bssid[5]);
		tempptr = &sndsckbff[40];
		sprintf((char *)tempptr,"Current Key Space");
		tempptr = &sndsckbff[60];
		sprintf((char *)tempptr,"%02X %02X %02X %02X %02X",sa,sb,0x00,0x00,0x00);
		//printf("send socket buffer\n %s\n",sndsckbff);
      		amtts=80;
      	}
}

		if(amtts > 0)
		{
			// Send back received data
			if (send(clientsock, sndsckbff, amtts, 0) != amtts) {
	#ifndef CURSES
			printf("Failed to send bytes to client\n");
	#endif
			}
		}
      }
      close(clientsock);
			//break;
		}
		
	}

	

	exit(0);
	return 0;
}


