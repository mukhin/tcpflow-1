/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.4  1999/04/13 23:17:55  jelson
 * More portability fixes.  All system header files now conditionally
 * included from sysdep.h.
 *
 * Integrated patch from Johnny Tevessen <j.tevessen@gmx.net> for Linux
 * systems still using libc5.
 *
 * Revision 1.3  1999/04/13 01:38:10  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

static char *cvsid = "$Id$";

#include "tcpflow.h"



/* The DLT_NULL packet header is 4 bytes long. It contains a network
 * order 32 bit integer that specifies the family, e.g. AF_INET */
#define	NULL_HDRLEN 4

void dl_null(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;
  u_int family;

  if (length != caplen) {
    DEBUG(6) ("warning: only captured %d bytes of %d byte null frame",
	  caplen, length);
  }

  if (caplen < NULL_HDRLEN) {
    DEBUG(6) ("warning: received incomplete null frame");
    return;
  }

  /* make sure this is AF_INET */
  memcpy((char *)&family, (char *)p, sizeof(family));
  if (family != AF_INET) {
    DEBUG(6) ("warning: received non-AF_INET null frame");
    return;
  }

  process_ip(p + NULL_HDRLEN, caplen - NULL_HDRLEN);
}




void dl_ethernet(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;
  struct ether_header *eth_header = (struct ether_header *) p;

  if (length != caplen) {
    DEBUG(6) ("warning: only captured %d bytes of %d byte ether frame",
	  caplen, length);
  }

  if (caplen < sizeof(struct ether_header)) {
    DEBUG(6) ("warning: received incomplete ethernet frame");
    return;
  }

  /* we're only expecting IP datagrams, nothing else */
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
    DEBUG(6) ("warning: received ethernet frame with unknown type %x",
	  ntohs(eth_header->ether_type));
    return;
  }

  process_ip(p + sizeof(struct ether_header),
	     caplen - sizeof(struct ether_header));
}


/* The DLT_PPP packet header is 4 bytes long.  We just move past it
 * without parsing it.  */
#define	PPP_HDRLEN 4

void dl_ppp(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;

  if (length != caplen) {
    DEBUG(6) ("warning: only captured %d bytes of %d byte PPP frame",
	  caplen, length);
  }

  if (caplen < PPP_HDRLEN) {
    DEBUG(6) ("warning: received incomplete PPP frame");
    return;
  }

  process_ip(p + PPP_HDRLEN, caplen - PPP_HDRLEN);
}


/* RAW: just a raw IP packet, no encapsulation */
void dl_raw(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  u_int caplen = h->caplen;
  u_int length = h->len;

  if (length != caplen) {
    DEBUG(6) ("warning: only captured %d bytes of %d byte raw frame",
	  caplen, length);
  }

  process_ip(p, caplen);
}


pcap_handler find_handler(int datalink_type, char *device)
{
  int i;

  struct {
    pcap_handler handler;
    int type;
  } handlers[] = {
    { dl_null, DLT_NULL },
#ifdef DLT_RAW
    { dl_raw, DLT_RAW },
#endif
    { dl_ethernet, DLT_EN10MB },
    { dl_ethernet, DLT_IEEE802 },
    { dl_ppp, DLT_PPP },
    { NULL, 0 },
  };

  DEBUG(2) ("looking for handler for datalink type %d for interface %s",
	datalink_type, device);

  for (i = 0; handlers[i].handler != NULL; i++)
    if (handlers[i].type == datalink_type)
      return handlers[i].handler;

  die("sorry - unknown datalink type %d on interface %s", datalink_type,
      device);
  /* NOTREACHED */
  return NULL;
}

