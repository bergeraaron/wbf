struct AP_BEACON_FRAME
{
	unsigned char frame_type;
	unsigned char frame_flag;
	unsigned short duration;
	unsigned char dest_addr[6];
	unsigned char src_addr[6];
	unsigned char bssid[6];
	unsigned short frag_seq;
	//wireless management frame 12 bytes
	double timestamp;
	unsigned short beacon_interval;
	unsigned short cap_info;
	unsigned char ap_flag;
	unsigned char wep_flag;
	unsigned char wpa_flag;
	//tagged parameters
	int ssid_len;
	char ssid_name[33];//max 32, but null termination
	char channel;
	int vndr_size;
	unsigned char vndr[32];
	int ckip_size;
	unsigned char * ckip;
};

struct SMALL_AP_BEACON_FRAME
{
	unsigned char bssid[6];
	unsigned char dest_addr[6];
	unsigned char src_addr[6];
	//tagged parameters
	int ssid_len;
	char ssid_name[33];//max 32, but null termination
	char channel[2];
	unsigned short cap_info;
	unsigned char wep_flag;
	unsigned char wpa_flag;
	unsigned int datanum;
};

struct DATA_FRAME
{
	unsigned char frame_type;
	unsigned char frame_flag;
	unsigned short duration;
	unsigned char bssid[6];
	unsigned char dest_addr[6];
	unsigned char src_addr[6];
	unsigned short frag_seq;
	//wireless data, iv section
};

struct DATA_FRAME_TO_CRACK
{
	unsigned char bssid[6];
	unsigned char iv[3];
	int data_size;
	unsigned char * encdata;
	//wireless data, iv section
};
