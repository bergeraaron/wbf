#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <signal.h>
#include <sqlite3.h>

#include "main.h"
#include "wbfwep.h"
#include "wbfsqlite3.h"


using namespace std;

void insert_key_sqlite3(sqlite3 *db,unsigned char * local_bssid,unsigned char * local_poskey)
{
	sqlite3_stmt *pStmt;
	char *zErrMsg = 0;
	int rc;
	char local_sqlite3_qry[512];
	printf("lets put it in the db\n");
	
	sprintf(local_sqlite3_qry,"insert into decryptkeys (BSSID,decryptkey) values('%02X:%02X:%02X:%02X:%02X:%02X','%02X%02X%02X%02X%02X');",local_bssid[0],local_bssid[1],local_bssid[2],local_bssid[3],local_bssid[4],local_bssid[5],local_poskey[0],local_poskey[1],local_poskey[2],local_poskey[3],local_poskey[4]);

	printf("%s\n",local_sqlite3_qry);
		
	sqlite3_prepare_v2(db,local_sqlite3_qry,sizeof(local_sqlite3_qry),&pStmt,0);
	sqlite3_reset(pStmt);
	while( (rc=sqlite3_step(pStmt)) != SQLITE_DONE )
	{
		if( rc == SQLITE_ROW )
			{printf("Correctly inserted into db\n");}
		else if( rc == SQLITE_BUSY )
			{printf("Step: BUSY\n") ;continue;}
		else if( rc == SQLITE_ERROR )
			{printf("SQL SELECT error: %s\n", sqlite3_errmsg(db));break;}
		else if( rc == SQLITE_MISUSE )
			{printf("Step: MISUSE\n");break;}
	}
	sqlite3_finalize(pStmt);
}


void check_ssid_sqlite3(sqlite3 *db,unsigned char * local_bssid, char * localssid)
{
	sqlite3_stmt *pStmt;
//	char *zErrMsg = 0;
	int rc;
	char local_sqlite3_qry[512];
	unsigned char tmpssid[32];
	printf("lets look to see if we have something in the db\n");
			
	sprintf(local_sqlite3_qry,"select ESSID from wireless where BSSID ='%02X:%02X:%02X:%02X:%02X:%02X';",local_bssid[0],local_bssid[1],local_bssid[2],local_bssid[3],local_bssid[4],local_bssid[5]);

	printf("query string: %s\n",local_sqlite3_qry);
			
	sqlite3_prepare_v2(db,local_sqlite3_qry,sizeof(local_sqlite3_qry),&pStmt,0);
	sqlite3_reset(pStmt);
	while( (rc=sqlite3_step(pStmt)) != SQLITE_DONE )
	{
	        if( rc == SQLITE_ROW )
	        {
	        	//spam	
			printf("we have a key so we should check it\n");
			sprintf((char*)tmpssid,"%s",(sqlite3_column_text(pStmt,0)));
			printf("temp tmpssid: %s\n",tmpssid);
			

			//save our key
			sprintf((char *)localssid,"%s",tmpssid);
			printf("localssid: %s\n",localssid);
			break;
	        }
	        else if( rc == SQLITE_BUSY )
	        {printf("Step: BUSY\n");continue;}
	        else if( rc == SQLITE_ERROR )
	        {printf("SQL SELECT error: %s\n", sqlite3_errmsg(db));break;}
	        else if( rc == SQLITE_MISUSE )
	        {printf("Step: MISUSE\n");break;}
	}
	sqlite3_finalize(pStmt);
	return;
}
int check_ssid_enc_sqlite3(sqlite3 *db, unsigned char * local_bssid)
{
	sqlite3_stmt *pStmt;
//	char *zErrMsg = 0;
	int rc;
	int j = 0;
	int return_val = 1;
	char local_sqlite3_qry[512];
	char tempenc[128];
	//printf("lets look to see if we have something in the db\n");

	char none[64];
	char wep[64];

	for(j=0;j<64;j++)
	{
		none[j]=0;
		wep[j]=0;
	}	
	sprintf(none,"None");
	sprintf(wep,"WEP");

	sprintf(local_sqlite3_qry,"select Encryption from wireless where BSSID ='%02X:%02X:%02X:%02X:%02X:%02X';",local_bssid[0],local_bssid[1],local_bssid[2],local_bssid[3],local_bssid[4],local_bssid[5]);

	//printf("query string: %s\n",local_sqlite3_qry);
			
	sqlite3_prepare_v2(db,local_sqlite3_qry,sizeof(local_sqlite3_qry),&pStmt,0);
	sqlite3_reset(pStmt);
	while( (rc=sqlite3_step(pStmt)) != SQLITE_DONE )
	{
	        if( rc == SQLITE_ROW )
	        {
	        	//spam	
			//printf("we have an enc so we should check it\n");
			sprintf(tempenc,"%s",(sqlite3_column_text(pStmt,0)));
			printf("temp tmpssid: %s\n",tempenc);

			if(strncmp(none,tempenc,4) == 0)
			{
				printf("No Enc\n");
				return_val = -1;
			}
			if(strncmp(wep,tempenc,3) == 0)
			{
				printf("WEP Enc\n");
				return_val = 1;
			}
			break;
	        }
	        else if( rc == SQLITE_BUSY )
	        {printf("Step: BUSY\n");continue;}
	        else if( rc == SQLITE_ERROR )
	        {printf("SQL SELECT error: %s\n", sqlite3_errmsg(db));break;}
	        else if( rc == SQLITE_MISUSE )
	        {printf("Step: MISUSE\n");break;}
	}
	sqlite3_finalize(pStmt);
	return return_val;
}

bool check_key_sqlite3(sqlite3 *db,unsigned char * local_bssid, unsigned char * key, int datactr,DATA_FRAME_TO_CRACK** dataframes)
{
	sqlite3_stmt *pStmt;
//	char *zErrMsg = 0;
	int rc;
	char local_sqlite3_qry[512];
	unsigned char local_poskey[10];
	unsigned char tmpkey[32];
	unsigned int key_len=0;
	printf("lets look to see if we have something in the db\n");
			
	sprintf(local_sqlite3_qry,"select decryptkey from decryptkeys where BSSID ='%02X:%02X:%02X:%02X:%02X:%02X';",local_bssid[0],local_bssid[1],local_bssid[2],local_bssid[3],local_bssid[4],local_bssid[5]);

	printf("query string: %s\n",local_sqlite3_qry);
			
	sqlite3_prepare_v2(db,local_sqlite3_qry,sizeof(local_sqlite3_qry),&pStmt,0);
	sqlite3_reset(pStmt);
	while( (rc=sqlite3_step(pStmt)) != SQLITE_DONE )
	{
	        if( rc == SQLITE_ROW )
	        {
	        	//spam	
			printf("we have a key so we should check it\n");
			sprintf((char*)tmpkey,"%s",(sqlite3_column_text(pStmt,0)));
			printf("temp key: %s\n",tmpkey);
			key_len = strlen((char*)tmpkey);
			printf("key_len: %d\n",key_len);
			string_to_key((char*)tmpkey,local_poskey,key_len);

	      		printf("possible key!\n");
	      		for(int i =0;i< key_len / 2;i++)
	      			printf("%02X",local_poskey[i]);
	      		printf("\n\n");
			bool areweok = verify_the_key(dataframes, datactr,local_bssid,local_poskey,(key_len/2));
			//save our key
			sprintf((char *)key,"%s",tmpkey);
			printf("key: %s\n",key);
			if(areweok)
			{
				printf("we have a valid key!\n");
				return true;
			}
			else
			{
				printf("this is not a valid key :(\n");	
				return false;
			}
	        }
	        else if( rc == SQLITE_BUSY )
	        {printf("Step: BUSY\n");continue;}
	        else if( rc == SQLITE_ERROR )
	        {printf("SQL SELECT error: %s\n", sqlite3_errmsg(db));break;}
	        else if( rc == SQLITE_MISUSE )
	        {printf("Step: MISUSE\n");break;}
	}
	sqlite3_finalize(pStmt);
	return false;
}

void string_to_key(char * temp_key, unsigned char * out_key,unsigned int t_key_len)
{
	
	char tmp[16][2];
	//unsigned char out_key[5];
	unsigned char t1,t2;
	int i=0,j=0;
	
	for(i=0;i < t_key_len / 2; i++)
	{
		
		tmp[i][0] = temp_key[j++];
		tmp[i][1] = temp_key[j++];
	}
/*
	for(int i=0;i < t_key_len / 2; i++)
		printf("%c%c\n",tmp[i][0],tmp[i][1]);
	
	printf("begin conversion\n");
*/
for(int i=0;i<t_key_len / 2;i++)
{
	//first octet
	if(tmp[i][0] == 'A')
		t1 = 10;
	else if(tmp[i][0] == 'B')
		t1 = 11;
	else if(tmp[i][0] == 'C')
		t1 = 12;
	else if(tmp[i][0] == 'D')
		t1 = 13;
	else if(tmp[i][0] == 'E')
		t1 = 14;
	else if(tmp[i][0] == 'F')
		t1 = 15;
        else if(tmp[i][0] == '0')
                t1 = 0;
        else if(tmp[i][0] == '1')
                t1 = 1;
        else if(tmp[i][0] == '2')
                t1 = 2;
        else if(tmp[i][0] == '3')
                t1 = 3;
        else if(tmp[i][0] == '4')
                t1 = 4;
        else if(tmp[i][0] == '5')
                t1 = 5;
        else if(tmp[i][0] == '6')
                t1 = 6;
        else if(tmp[i][0] == '7')
                t1 = 7;
        else if(tmp[i][0] == '8')
                t1 = 8;
        else if(tmp[i][0] == '9')
                t1 = 9;

	//second octet
	if(tmp[i][1] == 'A')
		t2 = 10;
	else if(tmp[i][1] == 'B')
		t2 = 11;
	else if(tmp[i][1] == 'C')
		t2 = 12;
	else if(tmp[i][1] == 'D')
		t2 = 13;
	else if(tmp[i][1] == 'E')
		t2 = 14;
	else if(tmp[i][1] == 'F')
		t2 = 15;
        else if(tmp[i][1] == '0')
                t2 = 0;
        else if(tmp[i][1] == '1')
                t2 = 1;
        else if(tmp[i][1] == '2')
                t2 = 2;
        else if(tmp[i][1] == '3')
                t2 = 3;
        else if(tmp[i][1] == '4')
                t2 = 4;
        else if(tmp[i][1] == '5')
                t2 = 5;
        else if(tmp[i][1] == '6')
                t2 = 6;
        else if(tmp[i][1] == '7')
                t2 = 7;
        else if(tmp[i][1] == '8')
                t2 = 8;
        else if(tmp[i][1] == '9')
                t2 = 9;

//	printf("t1: %d %02X t2: %d %02X\n",t1,t1,t2,t2);
	out_key[i] = (t1*16) + t2;
//	printf("outkey in dec: %d in hex: %02X \n",out_key[i],out_key[i]);
}
/*
	printf("out key\n");
	for(int i=0;i < 5; i++)
	{
		printf("%02X\n",out_key[i]);
	}
*/
}


