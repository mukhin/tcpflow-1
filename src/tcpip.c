#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "tcpflow.h"

#include <netinet/in.h>
#include <netinet/ip.h>


extern int console_only;
extern int bytes_per_flow;

/*************************************************************************/


/* This is called when we receive an IP datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
void process_ip(const char *data, u_int32_t caplen)
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
  if (ip_header->ip_p != IPPROTO_TCP)
    return;

  /* check and see if we got everything.  NOTE: we must use
   * ip_total_len after this, because we may have captured bytes
   * beyond the end of the packet (e.g. ethernet padding). */
  ip_total_len = ntohs(ip_header->ip_len);
  if (caplen < ip_total_len) {
    DEBUG(6) ("warning: captured only %d bytes of %d-byte IP datagram",
	 caplen, ip_total_len);
  }

  /* XXX - throw away everything but fragment 0; this version doesn't
   * know how to do fragment reassembly. */
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

  /* do TCP processing */
  process_tcp(data + ip_header_len, ip_total_len - ip_header_len,
	      ntohl(ip_header->ip_src.s_addr),
	      ntohl(ip_header->ip_dst.s_addr));
}


void process_tcp(const char *data, u_int32_t length, u_int32_t src,
		 u_int32_t dst)
{
  struct tcphdr *tcp_header = (struct tcphdr *) data;
  flow_t this_flow;
  u_int tcp_header_len;
  tcp_seq seq;

  if (length < sizeof(struct tcphdr)) {
    DEBUG(6) ("received truncated TCP segment!");
    return;
  }

  /* calculate the total length of the TCP header including options */
  tcp_header_len = tcp_header->th_off * 4;

  /* return if this packet doesn't have any data (e.g., just an ACK) */
  if (length <= tcp_header_len)
    return;

  /* fill in the flow_t structure with info that identifies this flow */
  this_flow.src = src;
  this_flow.dst = dst;
  this_flow.sport = ntohs(tcp_header->th_sport);
  this_flow.dport = ntohs(tcp_header->th_dport);
  seq = ntohl(tcp_header->th_seq);

  /*  printf("%s: %d\n", flow_filename(this_flow), HASH_FLOW(this_flow)); */

  if (console_only) {
    print_packet(this_flow, data+tcp_header_len, length - tcp_header_len);
  } else {
    store_packet(this_flow, data+tcp_header_len, length - tcp_header_len, seq);
  }
}


void print_packet(flow_t flow, const char *data, u_int32_t length)
{
  printf("%s: ", flow_filename(flow));
  while (length) {
    if (isprint(*data) || *data == '\n' || *data == '\r')
      putchar(*data);
    else
      putchar('.');
    length--;
    data++;
  }
  putchar('\n');
}



void store_packet(flow_t flow, const char *data, u_int32_t length,
		  u_int32_t seq)
{
  flow_state_t *state;
  tcp_seq offset;
  fpos_t fpos;

  /* see if we have state about this flow; if not, create it */
  if ((state = find_flow_state(flow)) == NULL) {
    state = create_flow_state(flow, seq);
  }

  /* if we're done collecting for this flow, return now */
  if (IS_SET(state->flags, FLOW_FINISHED))
    return;

  /* calculate the offset into this flow -- should handle seq num
   * wrapping correctly because tcp_seq is the right size */
  offset = seq - state->isn;

  /* I want to guard against receiving a packet with a sequence number
   * slightly less than what we consider the ISN to be; the max
   * (though admittedly non-scaled) window of 64K should be enough */
  if (offset >= 0xffff0000) {
    DEBUG(2) ("dropped packet with seq < isn on %s", flow_filename(flow));
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
  if (state->fp == NULL) {
    if (open_file(state) == NULL) {
      return;
    }
  }

  /* We are go for launch!  Everything's ready for us to do a write. */

  /* reduce length if it goes beyond the number of bytes per flow */
  if (bytes_per_flow && (offset + length > bytes_per_flow)) {
    SET_BIT(state->flags, FLOW_FINISHED);
    length = bytes_per_flow - offset;
  }

  /* if we're not at the correct point in the file, seek there */
  if (offset != state->pos) {
    fpos = offset;
    fsetpos(state->fp, &fpos);
  }

  /* write the data into the file */
  DEBUG(11) ("%s: writing %d bytes @%d", flow_filename(state->flow),
	  length, offset);

  if (fwrite(data, length, 1, state->fp) < 0) {
    DEBUG(1) ("write to %s failed: %s", flow_filename(state->flow),
	  strerror(errno));
  }
  fflush(state->fp);

  /* remember the position for next time */
  state->pos = offset + length;

  if (IS_SET(state->flags, FLOW_FINISHED)) {
    DEBUG(5) ("%s: stopping capture", flow_filename(state->flow));
    close_file(state);
  }
}
