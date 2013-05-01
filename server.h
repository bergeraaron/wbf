u_int32_t chksum_crc32 (unsigned char *block, unsigned int length);
void chksum_crc32gentab ();

void insert_key_sqlite3(sqlite3 *db,unsigned char * local_bssid,unsigned char * local_poskey);
bool check_key_sqlite3(sqlite3 *db,unsigned char * local_bssid);

bool check_bssid(SMALL_AP_BEACON_FRAME** LAParray, int lctr,unsigned char * local_bssid);
int return_bssid_place(SMALL_AP_BEACON_FRAME** LAParray, int lctr,unsigned char * local_bssid);
unsigned int check_for_data(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid);
unsigned int get_smallest_data_size(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid);
bool verify_the_key(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid, unsigned char * key,unsigned int v_key_len);
void string_to_key(char * temp_key, unsigned char * out_key,unsigned int t_key_len);
