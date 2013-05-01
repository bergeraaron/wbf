#include <stdio.h>
#include <string.h>
#include "wbfncurses.h"

void scr_init(int * n_row,int * n_col)
{
        //start curses
        initscr();
        noecho();
        //turn keypad on
        keypad(stdscr, TRUE);

        //get max size of std window
        getmaxyx(stdscr,*n_row,*n_col);

        if(*n_row > MAXROW)
        {*n_row=MAXROW;}
        if(*n_col > MAXCOL)
        {*n_col=MAXCOL;}

}

void printtemplate(int row,int col)
{
        for(int i=0;i < col;i++)
        {
                mvaddch(0,i,'-');
                mvaddch(row-1,i,'-');
        }

        for(int i=0;i < row;i++)
        {
                mvaddch(i,0,'|');
                mvaddch(i,col-1,'|');
        }

	mvprintw(1,1,"SSID");

	mvprintw(3,1,"BSSID");
//	mvprintw(BSSIDx,1,"00:11:22:33:44:55");
	mvprintw(5,1,"Current Key Space");
//	mvprintw(CKSx,1,"00:BE:EF:BE:EF");
	mvprintw(7,1,"Last Tested Key");
//	mvprintw(LTKx,1,"00:BE:EF:BE:EF");
	mvprintw(9,1,"Status");
//	mvprintw(KSTATx,1,"KEY FOUND");
}

void printssid(char * ssid)
{
	int len = strlen(ssid);
	if(len > (MAXCOL - 2))
	{
		char t_ssid[MAXCOL];
		for(int i=0;i<MAXCOL;i++)
		{t_ssid[i]=ssid[i];}
		mvprintw(SSIDx,1,t_ssid);
	}
	else
	{mvprintw(SSIDx,1,ssid);}
	refresh();
}
void printbssid(char * bssid)
{
	mvprintw(BSSIDx,1,bssid);
	refresh();
}
void printcks(char * cks)
{
	mvprintw(CKSx,1,cks);
	refresh();
}
void printltk(char * ltk)
{
	mvprintw(LTKx,1,ltk);
	refresh();
}
void printstat(char * status)
{
	mvprintw(KSTATx,1,status);
	refresh();
}

