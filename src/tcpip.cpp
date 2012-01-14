/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Id: tcpip.c,v 1.13 2001/08/24 05:36:14 jelson Exp $
 *
 * $Log: tcpip.c,v $
 * Revision 1.13  2001/08/24 05:36:14  jelson
 * fflush stdout in console print mode, from suggestion of Andreas
 * Schweitzer <andy@physast.uga.edu>, who says "Otherwise, I can't
 * redirect or pipe the console output. At least on FreeBSD. I will check
 * later today if this also cures the same problems I had on OpenBSD."
 *
 * Revision 1.12  2000/12/08 07:32:39  jelson
 * Took out the (broken) support for fgetpos/fsetpos.  Now we always simply
 * use fseek and ftell.
 *
 * Revision 1.11  1999/04/21 01:40:16  jelson
 * DLT_NULL fixes, u_char fixes, additions to configure.in, man page update
 *
 * Revision 1.10  1999/04/20 19:39:19  jelson
 * changes to fix broken localhost (DLT_NULL) handling
 *
 * Revision 1.9  1999/04/14 22:17:40  jelson
 * (re-)fixed checking of fwrite's return value
 *
 * Revision 1.8  1999/04/14 17:59:59  jelson
 * now correctly checking the return value of fwrite
 *
 * Revision 1.7  1999/04/14 03:02:39  jelson
 * added typecasts for portability
 *
 * Revision 1.6  1999/04/13 23:17:56  jelson
 * More portability fixes.  All system header files now conditionally
 * included from sysdep.h.
 *
 * Integrated patch from Johnny Tevessen <j.tevessen@gmx.net> for Linux
 * systems still using libc5.
 *
 * Revision 1.5  1999/04/13 01:38:15  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

#include "tcpflow.h"
#include <netinet/ip6.h>		/*  SLG */
#include <iostream>
/*************************************************************************/

/* convert all non-printable characters to '.' (period).  not
 * thread-safe, obviously, but neither is most of the rest of this. */
u_char *do_formatting(const u_char *data, u_int32_t length, u_int32_t* b_length, const char* tm_buffer);

/* convert all non-printable characters to '.' (period).  not
 * thread-safe, obviously, but neither is most of the rest of this.
 */
static u_char *do_strip_nonprint(const u_char *data, u_int32_t length)
{
    static u_char buf[SNAPLEN];
    u_char *write_ptr;

    write_ptr = buf;
    while (length) {
	if (isprint(*data) || (*data == '\n') || (*data == '\r'))
	    *write_ptr = *data;
	else
	    *write_ptr = '.';
	write_ptr++;
	data++;
	length--;
    }

    return buf;
}



/* print the contents of this packet to the console */
void tcpip::print_packet(const u_char *data, u_int32_t length, const char* tm_buffer)
{    
    /* green, blue, read */
    const char *color[3] = { "\033[0;32m", "\033[0;34m", "\033[0;31m" };

    if(bytes_per_flow>0){
	if(bytes_printed>bytes_per_flow) return; /* too much has been printed */
	if(length > bytes_per_flow - bytes_printed){
	    length = bytes_per_flow - bytes_printed; /* can only output this much */
	    if(length==0) return;
	}
    }

#ifdef HAVE_PTHREAD
    if(semlock){
	if(sem_wait(semlock)){
	    fprintf(stderr,"%s: attempt to acquire semaphore failed: %s\n",progname,strerror(errno));
	    exit(1);
	}
    }
#endif

    if (use_color) {
	if (dir_cs) fputs(color[1],stdout);
	if (dir_sc) fputs(color[2],stdout);
    }

  if (print_time_per_line || print_datetime_per_line) {
    printf("%s", tm_buffer);
  }

    if (suppress_header == 0) {
	printf("%s: ", flow_pathname.c_str());
    }

    fwrite(data, length, 1, stdout);
    bytes_printed += length;

    if (use_color) printf("\033[0m");

    putchar('\n');
    fflush(stdout);

#ifdef HAVE_PTHREAD
    if(semlock){
	if(sem_post(semlock)){
	    fprintf(stderr,"%s: attempt to post semaphore failed: %s\n",progname,strerror(errno));
	    exit(1);
	}
    }
#endif
}


/* store the contents of this packet to its place in its file */
void tcpip::store_packet(const u_char *data, u_int32_t length, u_int32_t seq, int syn_set)
{
    /* If we got a SYN reset the sequence number */
    if (syn_set) {
	DEBUG(50) ("resetting isn due to extra SYN");
	isn = seq - pos +1;
    }

    /* if we're done collecting for this flow, return now */
    if (finished) return;

    /* calculate the offset into this flow -- should handle seq num
     * wrapping correctly because tcp_seq is the right size */
    tcp_seq offset = seq - isn;

    /* I want to guard against receiving a packet with a sequence number
     * slightly less than what we consider the ISN to be; the max
     * (though admittedly non-scaled) window of 64K should be enough */
    if (offset >= 0xffff0000) {
	DEBUG(2) ("dropped packet with seq < isn on %s", flow_pathname.c_str());
	return;
    }

    /* reject this packet if it falls entirely outside of the range of
     * bytes we want to receive for the flow */
    if (bytes_per_flow && (offset > bytes_per_flow))
	return;

    /* if we don't have a file open for this flow, try to open it.
     * return if the open fails.  Note that we don't have to explicitly
     * save the return value because open_file() puts the file pointer
     * into the structure for us. */
    if (fp == NULL) {
	if (open_file() == NULL) {
	    return;
	}
    }

    /* We are go for launch!  Everything's ready for us to do a write. */

    /* reduce length if it goes beyond the number of bytes per flow */
    if (bytes_per_flow && (offset + length > bytes_per_flow)) {
	finished = true;
	length = bytes_per_flow - offset;
    }

    /* if we're not at the correct point in the file, seek there */
    if (offset != pos) {
	fseek(fp, offset, SEEK_SET);
    }

    /* write the data into the file */
    DEBUG(25) ("%s: writing %ld bytes @%ld", flow_pathname.c_str(),
	       (long) length, (long) offset);

    if (fwrite(data, length, 1, fp) != 1) {
	/* sigh... this should be a nice, plain DEBUG statement that
	 * passes strerrror() as an argument, but SunOS 4.1.3 doesn't seem
	 * to have strerror. */
	if (debug_level >= 1) {
	    DEBUG(1) ("write to %s failed: ", flow_pathname.c_str());
	    perror("");
	}
    }
    fflush(fp);

    /* remember the position for next time */
    pos = offset + length;

    if (finished) {
	DEBUG(5) ("%s: stopping capture", flow_pathname.c_str());
	close_file();
    }
}

/*
 * Called to processes a tcp packet
 */
#define TM_BUFFER_LENGTH 40

void tcpip::process_tcp(const struct timeval *ts,const u_char *data, u_int32_t length,
			const ipaddr &src, const ipaddr &dst,int32_t vlan,sa_family_t family)
{
    struct tcphdr *tcp_header = (struct tcphdr *) data;
    flow_addr this_flow;
    u_int tcp_header_len;
    tcp_seq seq;

    if (length < sizeof(struct tcphdr)) {
	DEBUG(6) ("received truncated TCP segment!");
	return;
    }

    /* calculate the total length of the TCP header including options */
    tcp_header_len = tcp_header->th_off * 4;

    /* fill in the flow_addr structure with info that identifies this flow */
    this_flow.src = src;
    this_flow.dst = dst;
    this_flow.family = family;
    this_flow.sport = ntohs(tcp_header->th_sport);
    this_flow.dport = ntohs(tcp_header->th_dport);

    seq = ntohl(tcp_header->th_seq);
    int syn_set = IS_SET(tcp_header->th_flags, TH_SYN);
    /* recalculate the beginning of data and its length, moving past the
     * TCP header
     */
    data   += tcp_header_len;
    length -= tcp_header_len;

    /* see if we have state about this flow; if not, create it (from Debian patch 10) */
    tcpip *state = tcpip::find_tcpip(this_flow);
    uint64_t connection_count = 0;
    if(state){
	/* If offset will be too much, throw away this_flow and create a new one */
	tcp_seq isn2 = state->isn;		// local copy
	if(syn_set){
	    isn2 = seq - state->pos + 1;
	}
	tcp_seq offset = seq - state->isn;
	if(offset>min_skip){
	    connection_count = state->flow.connection_count+1;
	    tcpip::remove_tcpip(this_flow);
	    state = 0;
	}
    }
    if (state==NULL){
	state = tcpip::create_tcpip(this_flow, vlan, seq, *ts,connection_count);
    }

    if (IS_SET(tcp_header->th_flags, TH_FIN)){
	state->fin = true;
	DEBUG(50)("packet is FIN");
    }

    /* Handle empty packets (from Debian patch 10) */
    if (length == 0) {
	/* examine TCP flags for initial TCP handshake segments:
	 * - SYN means that the flow is a client -> server flow
	 * - SYN/ACK means that the flow is a server -> client flow.
	 */
	if ((state->isn - seq) == 0) {
	    if (IS_SET(tcp_header->th_flags, TH_SYN) && IS_SET(tcp_header->th_flags, TH_ACK)) {
		state->dir_sc = true;
		DEBUG(50) ("packet is handshake SYN/ACK");
		/* If the SYN flag is set the first data byte is offset by one,
		 * account for it (note: if we're here we have just created
		 * state, so it's safe to change isn).
		 */
		state->isn++;
	    } else if (IS_SET(tcp_header->th_flags, TH_SYN)) {
		state->dir_cs = true;
		DEBUG(50) ("packet is handshake SYN");
		state->isn++;
	    }
	}
	DEBUG(50) ("got TCP segment with no data");
	return;
    }

  static char tm_buffer[TM_BUFFER_LENGTH];
  if (print_time_per_line) {
    format_timestamp(tm_buffer, TM_BUFFER_LENGTH, ts, 0);
  }
  else if (print_datetime_per_line) {
    format_timestamp(tm_buffer, TM_BUFFER_LENGTH, ts, 1);
  }

  /* store the length of the data */
  u_int32_t buffer_length = length;
  data = do_formatting(data, length, &buffer_length, tm_buffer);

    /* strip nonprintable characters if necessary */
//    if (strip_nonprint) data = do_strip_nonprint(data, length);

    /* store or print the output */
    if (console_only) {
	state->print_packet(data, buffer_length, tm_buffer);
    } else {
	state->store_packet(data, buffer_length, seq, syn_set);
    }
}





/* This is called when we receive an IPv4 datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
void process_ip4(const struct timeval *ts,const u_char *data, u_int32_t caplen,int32_t vlan)
{
    const struct ip *ip_header = (struct ip *) data;
    u_int ip_header_len;
    u_int ip_total_len;

    /* make sure that the packet is at least as long as the min IP header */
    if (caplen < sizeof(struct ip)) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip_p != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip_p);
	return;
    }

    /* check and see if we got everything.  NOTE: we must use
     * ip_total_len after this, because we may have captured bytes
     * beyond the end of the packet (e.g. ethernet padding).
     */
    ip_total_len = ntohs(ip_header->ip_len);
    if (caplen < ip_total_len) {
	DEBUG(6) ("warning: captured only %ld bytes of %ld-byte IP datagram",
		  (long) caplen, (long) ip_total_len);
    }

    /* XXX - throw away everything but fragment 0; this version doesn't
     * know how to do fragment reassembly.
     */
    if (ntohs(ip_header->ip_off) & 0x1fff) {
	DEBUG(2) ("warning: throwing away IP fragment from X to X");
	return;
    }

    /* figure out where the IP header ends */
    ip_header_len = ip_header->ip_hl * 4;

    /* make sure there's some data */
    if (ip_header_len > ip_total_len) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    /* do TCP processing, faking an ipv6 address  */
    tcpip::process_tcp(ts,data + ip_header_len, ip_total_len - ip_header_len,
		ipaddr(ip_header->ip_src.s_addr),
		ipaddr(ip_header->ip_dst.s_addr),
		vlan,AF_INET);
}


/* This is called when we receive an IPv6 datagram.
 *
 * Note: we don't support IPv6 extended headers
 */


void process_ip6(const struct timeval *ts,const u_char *data, const u_int32_t caplen,const int32_t vlan)
{
    const struct ip6_hdr *ip_header = (struct ip6_hdr *) data;
    u_int16_t ip_payload_len;

    /* make sure that the packet is at least as long as the IPv6 header */
    if (caplen < sizeof(struct ip6_hdr)) {
	DEBUG(6) ("received truncated IPv6 datagram!");
	return;
    }


    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip6_nxt != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip6_nxt);
	return;
    }

    ip_payload_len = ntohs(ip_header->ip6_plen);

    /* make sure there's some data */
    if (ip_payload_len == 0) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    /* do TCP processing */

    tcpip::process_tcp(ts,
		data + sizeof(struct ip6_hdr),
		ip_payload_len,
		ipaddr(ip_header->ip6_src.s6_addr),
		ipaddr(ip_header->ip6_dst.s6_addr),
		vlan,AF_INET6);
}



/* This is called when we receive an IPv4 or IPv6 datagram.
 * This function calls process_ip4 or process_ip6
 */

void process_ip(const struct timeval *ts,const u_char *data, u_int32_t caplen,int32_t vlan)
{
    const struct ip *ip_header = (struct ip *) data;
    if (caplen < sizeof(struct ip)) {
	DEBUG(6) ("can't determine IP datagram version!");
	return;
    }

    if(ip_header->ip_v == 6) {
	process_ip6(ts,data, caplen,vlan);
    } else {
	process_ip4(ts,data, caplen,vlan);
    }
}

 
/* convert all non-printable characters to '.' (period).  not
 * thread-safe, obviously, but neither is most of the rest of this. */
u_char *do_formatting(const u_char *data, u_int32_t length, u_int32_t* b_length, const char* tm_buffer)
{
  u_int32_t tmp_length = 0;
  u_int32_t size_of_tm_buffer = strlen(tm_buffer);

  static u_char buf[SNAPLEN];
  u_char *write_ptr;

  write_ptr = buf;
  while (length) {
    if ((strip_nonprint && !(isprint(*data) || *data == '\n' || *data == '\r'))
      || (strip_nr && (*data == '\n' || *data == '\r'))) {
      *write_ptr = '.';
    }
    else {
      *write_ptr = *data;
    }
    write_ptr++;
    tmp_length++;
    if (!strip_nr && ((print_time_per_line || print_datetime_per_line) && (*data == '\n'))) {
      memcpy(write_ptr, tm_buffer,size_of_tm_buffer);
      write_ptr += size_of_tm_buffer;
      tmp_length += size_of_tm_buffer;
    }
    data++;
    length--;
  }

  *b_length = tmp_length;

  return buf;
}


