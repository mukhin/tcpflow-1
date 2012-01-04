/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Id: flow.c,v 1.6 1999/04/13 01:38:11 jelson Exp $
 *
 * $Log: flow.c,v $
 * Revision 1.6  1999/04/13 01:38:11  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

#include "tcpflow.h"
#include <assert.h>
#include <iostream>
#include <sstream>
#include <map>

#include <tr1/unordered_map>


static int max_fds;
static int next_slot;
static int current_time;
static tcpip **fd_ring;



/* Initialize our structures */
void init_tcpip()
{
    /* Find out how many files we can have open safely...subtract 4 for
     * stdin, stdout, stderr, and the packet filter; one for breathing
     * room (we open new files before closing old ones), and one more to
     * be safe.
     */
    max_fds = get_max_fds() - NUM_RESERVED_FDS;

    fd_ring = (tcpip **)calloc(sizeof(tcpip *), max_fds);
    next_slot = -1;
    current_time = 0;
}


/****************************************************************
 *** THE FLOW DATABASE
 ****************************************************************/

uint64_t tcpip::flow_counter = 0;
typedef std::map<flow_addr,tcpip *> flow_map_t; // should be unordered_map
static flow_map_t flow_map;
inline std::ostream & operator << (std::ostream &os,const flow_map_t &fm) {
    for(flow_map_t::const_iterator it=fm.begin();it!=fm.end();it++){
	//os << "first: " << it->first << " second: " << *it->second << "\n";
    }
    return os;
}

/* Find previously a previously created flow state in the database.
 */
tcpip *tcpip::find_tcpip(const flow_addr &flow)
{
    flow_map_t::const_iterator it = flow_map.find(flow);
    if (it==flow_map.end()){
	return NULL; // flow not found
    }
    return it->second;
}

/* Create a new flow state structure for a given flow.
 * Puts the flow in the map.
 * Returns a pointer to the new state.
 */

tcpip *tcpip::create_tcpip(const flow_addr &flowa, int32_t vlan,tcp_seq isn,const timeval &ts,uint64_t connection_count)
{
    /* create space for the new state */
    flow_t flow(flowa,vlan,ts,ts,tcpip::flow_counter++,connection_count);

    tcpip *new_tcpip = new tcpip(flow,isn);
    new_tcpip->last_access = current_time++;
    DEBUG(5) ("%s: new flow", new_tcpip->flow_pathname.c_str());

    flow_map[flow] = new_tcpip;

    return new_tcpip;
}

void tcpip::remove_tcpip(const flow_addr &flowa)
{
    flow_map.erase(flowa);
}

tcpip::tcpip(const flow_t &flow_,tcp_seq isn_):
    flow(flow_),isn(isn_),flow_pathname(),fp(0),pos(0),
    last_access(0),bytes_printed(0),fin(),finished(0),file_exists(0),dir_sc(0),dir_cs(0)
{
    flow_pathname = outdir + std::string("/") + flow.filename();
}


/****************************************************************
 *** Instance methods
 ****************************************************************/

/**
 * Close all of the flows in the fd_ring
 */
void flow_close_all()
{
    int i;
    for(i=0;i<max_fds;i++){
	if(fd_ring[i]){
	    fd_ring[i]->close_file();
	    fd_ring[i] = 0;
	}
    }
}



FILE *tcpip::attempt_fopen(const char *filename)
{
    /* If we've opened this file already, reopen it.  Otherwise create a
     * new file.  We purposefully overwrite files from previous runs of
     * the program.
     */
    if (file_exists) {
	DEBUG(5) ("%s: re-opening output file", filename);
	fp = fopen(filename, "r+");
    } else {
	DEBUG(5) ("%s: opening new output file", filename);
	fp = fopen(filename, "w");
    }

    return fp;
}


FILE *tcpip::open_file()
{
    int done;

    /* This shouldn't be called if the file is already open */
    if (fp) {
	DEBUG(20) ("huh -- trying to open already open file!");
	return fp;
    }

    /* Now try and open the file */
    do {
	if (attempt_fopen(flow_pathname.c_str()) != NULL) {
	    /* open succeeded... great */
	    done = 1;
	} else {
	    if (errno == ENFILE || errno == EMFILE) {
		/* open failed because too many files are open... close one
		 * and try again
		 */
		contract_fd_ring();
		DEBUG(5) ("too many open files -- contracting FD ring to %d", max_fds);
		done = 0;
	    } else {
		/* open failed for some other reason... give up */
		done = 1;
	    }
	}
    } while (!done);

    /* If the file isn't open at this point, there's a problem */
    if (fp == NULL) {
	/* we had some problem opening the file -- set FINISHED so we
	 * don't keep trying over and over again to reopen it
	 */
	finished = true;
	perror(flow_pathname.c_str());
	return NULL;
    }

    /* Now we decide which FD slot we use, and close the file that's
     * there (if any).  Note that even if tcpip is not NULL, its
     * associated file pointer may already be closed.  Note well that we
     * DO NOT free the state that we find in our slot; the state stays
     * around forever (pointed to by the hash table).  This table only
     * keeps a pointer to state structures that have open files so that
     * we can close them later.
     *
     * We are putting the close after the open so that we don't bother
     * closing files if the open fails.  (For this, we pay a price of
     * needing to keep a spare, idle FD around.) */

    if (++next_slot == max_fds) {
	/* take this opportunity to sort from oldest to newest --
	 * optimally we'd like to do this before every close, but that
	 * might take too long. */
	sort_fds();
	next_slot = 0;
    }

    /* close the next one in line */
    if (fd_ring[next_slot] != NULL){
	fd_ring[next_slot]->close_file();
    }

    /* put ourslves in its place */
    fd_ring[next_slot] = this;

    /* set flags and remember where in the file we are */
    file_exists = true;
    pos = ftell(fp);
    return fp;
}



/* Closes the file belonging to a flow -- returns 1 if a file was
 * actually closed, 0 otherwise (if it was already closed) */
int tcpip::close_file()
{
    struct timeval times[2];

    if (fp == NULL) return 0;

    times[0] = flow.tstart;
    times[1] = flow.tstart;

    DEBUG(5) ("%s: closing file", flow_pathname.c_str());
    /* close the file and remember that it's closed */
    fflush(fp);		/* flush the file */
    if(futimes(fileno(fp),times)){
	perror("futimes");
    }
    fclose(fp);
    fp = NULL;
    pos = 0;
    return 1;
}



/* This comparison function puts flows first in the array, and nulls
 * last.  Within the flows, they are ordered from least recently
 * accessed at the front, and most recently accessed at the end. */
int tcpip_compare(const void *a, const void *b)
{
    tcpip **x = (tcpip **)a;
    tcpip **y = (tcpip **)b;

    if (*x == NULL && *y == NULL)
	return 0;
    if (*x == NULL)
	return 1;
    if (*y == NULL)
	return -1;
    return ((*x)->last_access - (*y)->last_access);
}


/* Sort FDs in the fd_table according to the comparison function (see
 * comment above) */
void sort_fds()
{
    qsort(fd_ring, max_fds, sizeof(tcpip *), tcpip_compare);
}


/* We need to reduce the size of the fd ring by one FD.  We will
 * sort the FD ring, close the oldest (i.e. first) file descriptor,
 * shift everything down by one, and set max_fds to reflect the new
 * size. */
void contract_fd_ring()
{
    /* sort */
    sort_fds();

    /* make sure we're sane */
    if (fd_ring[0] == NULL) {
	die("we seem to be completely out of file descriptors");
    }

    /* close the oldest FD */
    fd_ring[0]->close_file();

    /* shift everything forward by one and count */
    int i=1;
    for (i = 1; i < max_fds && fd_ring[i] != NULL; i++)
	fd_ring[i-1] = fd_ring[i];

    /* remember that the ring is smaller now */
    max_fds = i-1;

    /* start at 0 (by setting to -1, since we're going to increment it) */
    next_slot = -1;
}


int32_t flow_t::NO_VLAN = -1;

std::string flow_t::filename()
{
    char buf[1024];
    char srcstr[INET6_ADDRSTRLEN+1];
    char dststr[INET6_ADDRSTRLEN+1];
    std::stringstream ss;

    if(opt_format_timestamp) {
	ss << tstart.tv_sec << "T";
    }

    switch(family){
    default:
    case AF_INET:
	snprintf(buf,sizeof(buf),
		 "%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d",
		 src.addr[0], src.addr[1], src.addr[2], src.addr[3], sport,
		 dst.addr[0], dst.addr[1], dst.addr[2], dst.addr[3], dport);
	ss << buf;
	break;
    case AF_INET6:
	snprintf(buf,sizeof(buf),
		 "%s.%05d-%s.%05d",
		 inet_ntop(family, src.addr, srcstr, sizeof(srcstr)),
		 sport,
		 inet_ntop(family, dst.addr, dststr, sizeof(dststr)),
		 dport);
	ss << buf;
    }

    if(vlan!=NO_VLAN){
	ss << "--" << vlan;
    }
    if(opt_format_connection_counter || connection_count>0){
	ss << "c" << connection_count;
    }

    return ss.str();
}





