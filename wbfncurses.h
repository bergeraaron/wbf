#include <ncurses.h>

#define MAXROW 20
#define MAXCOL 50

#define SSIDx 2
#define BSSIDx 4
#define CKSx 6
#define LTKx 8
#define KSTATx 10

void printtemplate(int row,int col);
void printssid(char * ssid);
void printbssid(char * bssid);
void printcks(char * cks);
void printltk(char * ltk);
void printstat(char * status);
void scr_init(int * n_row,int * n_col);

