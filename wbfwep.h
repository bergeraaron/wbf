u_int32_t chksum_crc32(unsigned char *block, unsigned int length);
void chksum_crc32gentab();
bool verify_the_key(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid, unsigned char * key,unsigned int v_key_len);
bool verify_the_key_packet_display(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid, unsigned char * key,unsigned int v_key_len);
