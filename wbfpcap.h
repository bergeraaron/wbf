#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

bool check_bssid(SMALL_AP_BEACON_FRAME** LAParray, int lctr,unsigned char * local_bssid);
int return_bssid_place(SMALL_AP_BEACON_FRAME** LAParray, int lctr,unsigned char * local_bssid);
unsigned int check_for_data(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid);
unsigned int get_smallest_data_size(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid);
unsigned int get_smallest_data_size_ignore_iv(DATA_FRAME_TO_CRACK** dataarray, int dctr,unsigned char * local_bssid,unsigned char iv1,unsigned char iv2,unsigned char iv3);
bool load_pcap_from_file(char * filename,char * errbuf,bool prism_flag,int & datactr,int & ctr);//,SMALL_AP_BEACON_FRAME** smallAParray,DATA_FRAME_TO_CRACK** dataframes

