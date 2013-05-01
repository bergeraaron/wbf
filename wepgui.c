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
#include <gtk/gtk.h>

#define BUILDER_XML_FILE "wepgui.xml"


char errbuf[PCAP_ERRBUF_SIZE];

int packet_len = 0;
int off=0;
int remain_size=0;
int temp_jump=0;
unsigned char lbssid[6];
pcap_t *handle;
struct pcap_pkthdr header;	/* The header that pcap gives us */
u_char *packet;			/* The actual packet */
const u_char *temppacket;	// The temp packet

int i,x=0;
int ctr=0;
int failed=0;
char time_temp[8];
int tocrack;
bool prism_flag = false;
unsigned char poskey[5];
unsigned char tmpkey[64];
unsigned int key_len=0;
//sqlite 3 stuff
sqlite3 *db;
sqlite3_stmt *pStmt;
bool sqlite3_flag = true;
char sqlite3_db[512];
char sqlite3_qry[512];
char *zErrMsg = 0;
int rc;
  
//packet structs
int vctr=0;
int datactr=0;
SMALL_AP_BEACON_FRAME** smallAParray = NULL;
SMALL_AP_BEACON_FRAME** validAParray = NULL;
DATA_FRAME_TO_CRACK** dataframes = NULL;

//server
int serversock, clientsock;
struct sockaddr_in echoserver, echoclient;
unsigned char sckbff[256];
unsigned char sndsckbff[256];
int amtts = 0;
int key_found=0;

int sa,sb,sc=0;

//state file
FILE * sFile;
char sfilename[32];

void shutnicely(int sig);
void close_file();

/* store the widgets which may need to be accessed in a typedef struct */
typedef struct
{
        GtkWidget               *window;
        GtkWidget               *statusbar;
        GtkTreeView             *aptree;
        guint                   statusbar_context_id;
        gchar                   *filename;
} WepBruteForceServer;

enum
{
  COL_ID = 0,
  COL_BSSID,
  COL_SSID,
  COL_ENC,
  COL_DATA,
  COL_KEY,
  COL_CONF,
  NUM_COLS
} ;



/* window callback prototypes */
void on_window_destroy (GtkObject *object, WepBruteForceServer *wbfs);
gboolean on_window_delete_event (GtkWidget *widget, GdkEvent *event,
                                 WepBruteForceServer *wbfs);

extern "C" void on_toolfileopen_activate (GtkMenuItem *menuitem, WepBruteForceServer *wbfs);
extern "C" void on_toolfileclose_activate (GtkMenuItem *menuitem, WepBruteForceServer *wbfs);
extern "C" void on_toolfilequit_activate (GtkMenuItem *menuitem, WepBruteForceServer *wbfs);

/* misc. function prototypes */
void error_message (const gchar *message);
gboolean init_app (WepBruteForceServer *wbfs);
gchar* get_open_filename (WepBruteForceServer *wbfs);
void load_file (WepBruteForceServer *wbfs, gchar *filename);
void load_pcap (WepBruteForceServer *wbfs, gchar *filename);
void reset_default_status (WepBruteForceServer *wbfs);


int main (int argc, char *argv[])
{
	chksum_crc32gentab();

	if(sqlite3_flag)
	{
	  printf("attempt to open the db\n");
	//sprintf(sqlite3_db,"wireless.dbl");
	//lets open the db
	  rc = sqlite3_open("wireless.dbl", &db);
	  printf("rc: %d\n",rc);
	  if( rc ){
	    printf("Can't open database: %s\n", sqlite3_errmsg(db));
	    sqlite3_close(db);
	    exit(1);
	  }
	  printf("db opened\n");
	}

        WepBruteForceServer      *wbfs;
        /* allocate the memory needed by our WepBruteForceServer struct */
        wbfs = g_slice_new (WepBruteForceServer);
        /* initialize GTK+ libraries */
        gtk_init (&argc, &argv);
        if (init_app (wbfs) == FALSE) return 1; /* error loading UI */
	gtk_widget_show_all (wbfs->window);
        /* enter GTK+ main loop */                   
        gtk_main ();
        /* free memory we allocated for TutorialTextEditor struct */
        g_slice_free (WepBruteForceServer, wbfs);
        return 0;
}
/*
We call error_message() any time we want to display an error message to the
user. It will both show an error dialog and log the error to the terminal
window.
*/
void error_message (const gchar *message)
{
        GtkWidget               *dialog;
        
        /* on_window_dellog to terminal window */
        g_warning (message);
        
        /* create an error message dialog and display modally to the user */
        dialog = gtk_message_dialog_new (NULL, 
                                         (GtkDialogFlags)(GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT),
                                         GTK_MESSAGE_ERROR,
                                         GTK_BUTTONS_OK,
                                         message);
        
        gtk_window_set_title (GTK_WINDOW (dialog), "Error!");
        gtk_dialog_run (GTK_DIALOG (dialog));      
        gtk_widget_destroy (dialog);         
}

/*
We call init_app() when our program is starting to load our WepBruteForceServer struct
with references to the widgets we need. This is done using GtkBuilder to read
the XML file we created using Glade.
*/
gboolean init_app (WepBruteForceServer *wbfs)
{
        GtkBuilder              *builder;
        GError                  *err=NULL;      
        guint                   id;

	//tree stuff
	GtkCellRenderer		*renderer;
	GtkTreeModel		*model;
	GtkListStore		*store;

        /* use GtkBuilder to build our interface from the XML file */
        builder = gtk_builder_new ();
        if (gtk_builder_add_from_file (builder, BUILDER_XML_FILE, &err) == 0)
        {
                error_message (err->message);
                g_error_free (err);
                return FALSE;
        }
        
        /* get the widgets which will be referenced in callbacks */
        wbfs->window = GTK_WIDGET (gtk_builder_get_object (builder, 
                                                             "main"));
        wbfs->statusbar = GTK_WIDGET (gtk_builder_get_object (builder, 
                                                                "mainstatusbar"));
        wbfs->aptree = GTK_TREE_VIEW(gtk_builder_get_object(builder, "aptree"));

	//treestuff
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (wbfs->aptree),
		                               -1,      
		                               "ID",  
		                               renderer,
		                               "text", COL_ID,
		                               NULL);
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (wbfs->aptree),
		                               -1,      
		                               "BSSID",  
		                               renderer,
		                               "text", COL_BSSID,
		                               NULL);

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (wbfs->aptree),
		                               -1,      
		                               "SSID",  
		                               renderer,
		                               "text", COL_SSID,
		                               NULL);
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (wbfs->aptree),
		                               -1,      
		                               "ENC",  
		                               renderer,
		                               "text", COL_ENC,
		                               NULL);
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (wbfs->aptree),
		                               -1,      
		                               "DATA",  
		                               renderer,
		                               "text", COL_DATA,
		                               NULL);

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (wbfs->aptree),
		                               -1,      
		                               "KEY",  
		                               renderer,
		                               "text", COL_KEY,
		                               NULL);

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (wbfs->aptree),
		                               -1,      
		                               "CONFIRMED",  
		                               renderer,
		                               "text", COL_CONF,
		                               NULL);

	store = gtk_list_store_new (NUM_COLS, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING);

	model = GTK_TREE_MODEL (store);
	gtk_tree_view_set_model (GTK_TREE_VIEW (wbfs->aptree), model);

	/* The tree view has acquired its own reference to the
	*  model, so we can drop ours. That way the model will
	*  be freed automatically when the tree view is destroyed */

	g_object_unref (model);

        /* connect signals, passing our TutorialTextEditor struct as user data */
        gtk_builder_connect_signals (builder, wbfs);
        /* free memory used by GtkBuilder object */
        g_object_unref (G_OBJECT (builder));
        
        /* set the default icon to the GTK "edit" icon */
        gtk_window_set_default_icon_name (GTK_STOCK_EDIT);
        
        /* setup and initialize our statusbar */
        id = gtk_statusbar_get_context_id (GTK_STATUSBAR (wbfs->statusbar),
                                           "WepBruteForceServer");
        wbfs->statusbar_context_id = id;
        reset_default_status (wbfs);
        
        /* set filename to NULL since we don't have an open/saved file yet */
        wbfs->filename = NULL;
        
        return TRUE;
}
/*
We call get_open_filename() when we want to get a filename to open from the
user. It will present the user with a file chooser dialog and return the 
newly allocated filename or NULL.
*/
gchar * get_open_filename (WepBruteForceServer *wbfs)
{
        GtkWidget               *chooser;
        gchar                   *filename=NULL;
                
        chooser = gtk_file_chooser_dialog_new ("Open File...",
                                               GTK_WINDOW (wbfs->window),
                                               GTK_FILE_CHOOSER_ACTION_OPEN,
                                               GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                               GTK_STOCK_OPEN, GTK_RESPONSE_OK,
                                               NULL);
                                               
        if (gtk_dialog_run (GTK_DIALOG (chooser)) == GTK_RESPONSE_OK)
        {
                filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (chooser));
        }
        
        gtk_widget_destroy (chooser);
        return filename;
}
/* 
We call load_file() when we have a filename and want to load it into the buffer
for the GtkTextView. The previous contents are overwritten.
*/
void load_file (WepBruteForceServer *wbfs, gchar *filename)
{
        GError                  *err=NULL;
        gchar                   *status;
        gchar                   *text;
        gboolean                result;

        /* add Loading message to status bar and  ensure GUI is current */
        status = g_strdup_printf ("Loading %s...", filename);
        gtk_statusbar_push (GTK_STATUSBAR (wbfs->statusbar),
                            wbfs->statusbar_context_id, status);
        g_free (status);
        while (gtk_events_pending()) gtk_main_iteration();
        
        /* get the file contents */
        result = g_file_get_contents (filename, &text, NULL, &err);
        if (result == FALSE)
        {
                /* error loading file, show message to user */
                error_message (err->message);
                g_error_free (err);
                g_free (filename);
        }
        
        /* now we can set the current filename since loading was a success */
        if (wbfs->filename != NULL) g_free (wbfs->filename);
        wbfs->filename = filename;
        
        /* clear loading status and restore default  */
        gtk_statusbar_pop (GTK_STATUSBAR (wbfs->statusbar),
                           wbfs->statusbar_context_id);
        reset_default_status (wbfs);
}

/*
We call reset_default_status() when we want to remove the last default status
and set it again based on the current file. This is typically after a file is
opened, saved, or a new file is created. "Default" simply means a non-temporary
status. It's typically something like "File: filename.txt"
*/
void reset_default_status (WepBruteForceServer *wbfs)
{
        gchar           *file;
        gchar           *status;
        
        if (wbfs->filename == NULL)
        {
                file = g_strdup ("(UNTITLED)");
        }
        else file = g_path_get_basename (wbfs->filename);
        
        status = g_strdup_printf ("File: %s", file);
        gtk_statusbar_pop (GTK_STATUSBAR (wbfs->statusbar),
                           wbfs->statusbar_context_id);
        gtk_statusbar_push (GTK_STATUSBAR (wbfs->statusbar),
                            wbfs->statusbar_context_id, status);
        g_free (status);
        g_free (file);
}
/* 
When our window is destroyed, we want to break out of the GTK main loop. We do
this by calling gtk_main_quit(). We could have also just specified gtk_main_quit
as the handler in Glade!
*/
void on_window_destroy (GtkObject *object, WepBruteForceServer *wbfs)
{
	shutnicely(1);
        gtk_main_quit();
}
/*
When the window is requested to be closed, we need to check if they have 
unsaved work. We use this callback to prompt the user to save their work before
they exit the application. From the "delete-event" signal, we can choose to
effectively cancel the close based on the value we return.
*/
gboolean on_window_delete_event (GtkWidget *widget, GdkEvent *event, WepBruteForceServer *wbfs)
{
        return FALSE;   /* propogate event */
}
/*
Called when the user clicks the 'Open' menu. We need to prompt for save if the
file has been modified, allow the user to choose a file to open, and then call
load_file() on that file.
*/
extern "C" void on_toolfileopen_activate (GtkMenuItem *menuitem, WepBruteForceServer *wbfs)
{
        gchar                   *filename;        
        filename = get_open_filename (wbfs);
        if (filename != NULL) load_pcap (wbfs, filename); 
}

extern "C" void on_toolfileclose_activate (GtkMenuItem *menuitem, WepBruteForceServer *wbfs)
{
	close_file();
}


/*
Called when the user clicks the 'Quit' menu. We need to prompt for save if the
file has been modified and then break out of the GTK+ main loop.
*/
extern "C" void on_toolfilequit_activate(GtkMenuItem *menuitem, WepBruteForceServer *wbfs)
{
	shutnicely(1);
        gtk_main_quit();
}

void load_pcap (WepBruteForceServer *wbfs, gchar *filename)
{
	gchar                   *status;
        // add Loading message to status bar and  ensure GUI is current
        status = g_strdup_printf ("Loading %s...", filename);
        gtk_statusbar_push (GTK_STATUSBAR (wbfs->statusbar),
                            wbfs->statusbar_context_id, status);
        g_free (status);
        while (gtk_events_pending()) gtk_main_iteration();


// now we can set the current filename since loading was a success
if (wbfs->filename != NULL) g_free (wbfs->filename);
wbfs->filename = filename;

// clear loading status and restore default
gtk_statusbar_pop (GTK_STATUSBAR (wbfs->statusbar),
                   wbfs->statusbar_context_id);
reset_default_status (wbfs);

	handle = pcap_open_offline(filename, errbuf);
	if (handle == NULL) {
	 fprintf(stderr, "Couldn't open file %s\n", errbuf);
	 return;
	}
	//file open, so lets loop through it

  while(1)
  {
  	off=0;
					
    if((temppacket = pcap_next(handle, &header)) == NULL)
      break;

//	printf("Jacked a packet with length of [%d]\n", header.len);

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
							if(vndr_size == 28 || vndr_size == 26 || vndr_size == 24 || vndr_size == 22)
							{
								//printf("possible wpa\n");
								int wpa_check = (packet[off+0] << 32) | (packet[off+1] << 16) | (packet[off+2] << 8) | packet[off+3];
								if(wpa_check == 0x0050F201)
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
//			unsigned char pr_ap_flag;
			unsigned char pr_wep_flag;
			unsigned char pr_wpa_flag;
			int pr_ssid_len;
			char pr_ssid_name[33];//max 32, but null termination
//			char pr_channel;
//			int pr_vndr_size;
//			unsigned char pr_vndr[32];
//			int pr_ckip_size;
//			unsigned char * pr_ckip;
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
						
						printf("%003d %02X:%02X:%02X:%02X:%02X:%02X ",place_in_array,smallAParray[place_in_array]->bssid[0],smallAParray[place_in_array]->bssid[1],smallAParray[place_in_array]->bssid[2],smallAParray[place_in_array]->bssid[3],smallAParray[place_in_array]->bssid[4],smallAParray[place_in_array]->bssid[5]);
						
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

printf("done with the file\n");


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

//spam
	GtkTreeModel		*model;
	GtkListStore		*store;
	GtkTreeIter		iter;
	char	enc[4];
	char 	confirm[4];
	char 	local_bssid[32];
	unsigned char testedkey[32];
	store = gtk_list_store_new (NUM_COLS, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING);

	for(int k =0;k < vctr;k++)
	{
		for(int t=0;t<32;t++)
		{
			local_bssid[t]=0;
			testedkey[t]=0;
		}
		for(int t=0;t<4;t++)
			confirm[t]=0;

		sprintf(local_bssid,"%02X:%02X:%02X:%02X:%02X:%02X",validAParray[k]->bssid[0],validAParray[k]->bssid[1],validAParray[k]->bssid[2],validAParray[k]->bssid[3],validAParray[k]->bssid[4],validAParray[k]->bssid[5]);

		if(validAParray[k]->wep_flag == 1)
			sprintf(enc,"WEP");
		else if(validAParray[k]->wpa_flag == 1)
			sprintf(enc,"WPA");
		else
			sprintf(enc,"---");

			bool returned = check_key_sqlite3(db,validAParray[k]->bssid,testedkey,datactr,dataframes);
			printf("testedkey: %s\n",testedkey);
			if(returned == true)
				sprintf(confirm,"YES");
			else
				sprintf(confirm,"NO");

	int ssid_len = strlen(validAParray[k]->ssid_name);
	if(ssid_len == 0)
	{
		//lets go find the ssid from the db
		check_ssid_sqlite3(db,validAParray[k]->bssid,validAParray[k]->ssid_name);
	}

	/* Append a row and fill in some data */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	      COL_ID, k,
	      COL_BSSID, local_bssid,
	      COL_SSID, validAParray[k]->ssid_name,
	      COL_ENC, enc,
	      COL_DATA, validAParray[k]->datanum,
	      COL_KEY,testedkey,
              COL_CONF,confirm,
	      -1);
	}//end of looking through the basestations

	model = GTK_TREE_MODEL (store);
	gtk_tree_view_set_model (GTK_TREE_VIEW (wbfs->aptree), model);

	/* The tree view has acquired its own reference to the
	*  model, so we can drop ours. That way the model will
	*  be freed automatically when the tree view is destroyed */

	g_object_unref (model);


}


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

        printf("validAParray: vctr:%d\n",vctr);
/*
        for(i = 0; i < vctr; i++) {
          free(validAParray[i]);
          i++;
         }
*/
         if(vctr > 0)
                free(validAParray);
        validAParray=NULL;
        vctr=0;

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

		exit(1);
}

void close_file()
{
        //clean up our main array for the aps
        printf("smallAParray: ctr:%d\n",ctr);

        for(i = 0; i < ctr; i++) {
          free(smallAParray[i]);
          i++;
         }
         if(ctr > 0)
                free(smallAParray);
	smallAParray=NULL;
	ctr=0;
//spam
        printf("validAParray: vctr:%d\n",vctr);
/*
        for(i = 0; i < vctr; i++) {
          free(validAParray[i]);
          i++;
         }
*/
         if(vctr > 0)
                free(validAParray);
        validAParray=NULL;
        vctr=0;
/**/
	 printf("dataframes: datactr:%d\n",datactr);
         for(i = 0; i < datactr; i++) {
          free(dataframes[i]->encdata);
          free(dataframes[i]);
          i++;
         }
         if(datactr > 0)
                free(dataframes);
	dataframes=NULL;
	datactr=0;
	//all data should be freed
}





