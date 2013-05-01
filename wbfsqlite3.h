#include <sqlite3.h>
//#include "wbfwep.h"
void insert_key_sqlite3(sqlite3 *db,unsigned char * local_bssid,unsigned char * local_poskey);
void check_ssid_sqlite3(sqlite3 *db,unsigned char * local_bssid, char * localssid);
int check_ssid_enc_sqlite3(sqlite3 *db, unsigned char * local_bssid);
bool check_key_sqlite3(sqlite3 *db,unsigned char * local_bssid,unsigned char * key, int datactr,DATA_FRAME_TO_CRACK** dataframes);
void string_to_key(char * temp_key, unsigned char * out_key,unsigned int t_key_len);

