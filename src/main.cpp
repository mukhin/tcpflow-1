/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Substantially upgraded by Simson Garfinkel <simsong@acm.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#define __MAIN_C__

#include "tcpflow.h"

#define DEFAULT_FILTER ""

#define ENABLE_GZIP 0


int debug_level = DEFAULT_DEBUG_LEVEL;
int no_promisc = 0;
uint64_t bytes_per_flow = 0;			/* -b option */
int max_flows = 0;
int max_desired_fds = 0;
int console_only = 0;
int suppress_header = 0;
int strip_nonprint = 0;
int use_color = 0;
u_int min_skip  = 1000000;
bool opt_format_connection_counter = false;
bool opt_format_timestamp = false;
int print_time_per_line = 0;
int print_datetime_per_line = 0;
int strip_nr = 0;

char error[PCAP_ERRBUF_SIZE];
const char *outdir = ".";
const char *progname = 0;

xml *xreport = 0;

#ifdef HAVE_PTHREAD
sem_t *semlock = 0;
#endif

#include <string>
#include <semaphore.h>

void print_usage()
{
    fprintf(stderr, "%s version %s\n\n",PACKAGE, VERSION);
    fprintf(stderr, "usage: %s [-chpsv] [-b max_bytes] [-d debug_level] [-f max_fds]\n", progname);
    fprintf(stderr, "          [-i iface] [-L semlock] [-r file] [-o outdir] [-X xmlfile]\n");
    fprintf(stderr, "          [-m min_bytes] [-F[ct]] [expression]\n\n");
    fprintf(stderr, "        -b: max number of bytes per flow to save\n");
    fprintf(stderr, "        -B: force binary output to console, even with -c or -C\n");
    fprintf(stderr, "        -c: console print only (don't create files)\n");
    fprintf(stderr, "        -C: console print only, but without the display of source/dest header\n");
    fprintf(stderr, "        -d: debug level; default is %d\n", DEFAULT_DEBUG_LEVEL);
    fprintf(stderr, "        -e: output each flow in alternating colors\n");
    fprintf(stderr, "        -f: maximum number of file descriptors to use\n");
    fprintf(stderr, "        -h: print this help message\n");
    fprintf(stderr, "        -i: network interface on which to listen\n");
    fprintf(stderr, "            (type \"ifconfig -a\" for a list of interfaces)\n");
    fprintf(stderr, "        -L: lock; specifies that writes are locked using a named semaphore\n");
    fprintf(stderr, "        -p: don't use promiscuous mode\n");
    fprintf(stderr, "        -r: read packets from tcpdump output file\n");
    fprintf(stderr, "        -S: strip end-of-line characters (change to '.')\n");
    fprintf(stderr, "        -s: strip non-printable characters (change to '.')\n");
    fprintf(stderr, "        -T: add date & time to the output\n");
    fprintf(stderr, "        -t: add time to the output\n");
    fprintf(stderr, "        -v: verbose operation equivalent to -d 10\n");
    fprintf(stderr, "        -o outdir   : specify output directory (default '.')\n");
    fprintf(stderr, "        -X filename : DFXML output to filename\n");
    fprintf(stderr, "        -m bytes    : specifies the minimum number of bytes that a stream may\n");
    fprintf(stderr, "                      skip before starting a new stream (default %d).\n",min_skip);
    fprintf(stderr, "        -Fc : append the connection counter to ALL filenames\n");
    fprintf(stderr, "        -Ft : prepend the timestamp to ALL filenames\n");
#if ENABLE_GZIP
    fprintf(stderr, "        -Z: do not decompress gzip-compressed HTTP transactions\n");
#endif
    fprintf(stderr, "expression: tcpdump-like filtering expression\n");
    fprintf(stderr, "\nSee the man page for additional information.\n\n");
}


void terminate(int sig)
{
    DEBUG(1) ("terminating");
    exit(0); /* libpcap uses onexit to clean up */
}


/**
 * Create the dfxml output
 */

static void dfxml_create(int argc,char **argv,std::string filename)
{
    xreport = new xml(filename,false);

    xreport->push("dfxml","xmloutputversion='1.0'");
    xreport->push("metadata",
		 "\n  xmlns='http://afflib.org/tcpflow/' "
		 "\n  xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
		 "\n  xmlns:dc='http://purl.org/dc/elements/1.1/'" );
    xreport->xmlout("dc:type","Feature Extraction","",false);
    xreport->pop();
    xreport->add_DFXML_creator(PACKAGE_NAME,PACKAGE_VERSION,xml::make_command_line(argc,argv));

    xreport->push("configuration");
    xreport->pop();			// configuration
}


int main(int argc, char *argv[])
{
    int arg, dlt;
    int need_usage = 0;
    int opt_Z = 0;

    const char *lockname = 0;
    char *device = NULL;
    char *infile = NULL;
    pcap_t *pd;
    struct bpf_program fcode;
    pcap_handler handler;


    progname = argv[0];
    init_debug(argv);
    opterr = 0;
    bool force_binary_output = false;
    const char *xmlout = 0;

    while ((arg = getopt(argc, argv, "Bb:cCd:eF:f:hi:L:m:o:pr:SsTtvX:Z")) != EOF) {
	switch (arg) {
	case 'b':
	    if ((bytes_per_flow = atoi(optarg)) < 0) {
		DEBUG(1) ("warning: invalid value '%s' used with -b ignored", optarg);
		bytes_per_flow = 0;
	    } else {
		DEBUG(10) ("capturing max of %"PRIu64" bytes per flow", bytes_per_flow);
	    }
	    break;
	case 'B':
	    force_binary_output = true; DEBUG(10) ("force binary output");
	    break;
	case 'C':
	    console_only = 1;		DEBUG(10) ("printing packets to console only");
	    suppress_header = 1;	DEBUG(10) ("packet header dump suppressed");
	    strip_nonprint = 1;		DEBUG(10) ("converting non-printable characters to '.'");
	    break;
	case 'c':
	    console_only = 1;		DEBUG(10) ("printing packets to console only");
	    strip_nonprint = 1;		DEBUG(10) ("converting non-printable characters to '.'");
	    break;
	case 'F':
	    for(const char *cc=optarg;*cc;cc++){
		switch(*cc){
		case 'c':opt_format_connection_counter = true;break;
		case 't':opt_format_timestamp = true;break;
		default:
		    fprintf(stderr,"-F invalid format specification '%c'\n",*cc);
		    need_usage = true;
		}
	    }
	    break;
	case 'm':
	    min_skip = atoi(optarg);    DEBUG(10) ("min_skip set to %d",min_skip); break;
  case 'S':
    strip_nr = 1;
    DEBUG(10) ("converting  end-of-line  characters to '.'");
  break;
	case 's':
	    strip_nonprint = 1;		DEBUG(10) ("converting non-printable characters to '.'"); break;
  case 'T':
    print_datetime_per_line = 1;
    DEBUG(10) ("add date & time to the output");
  break;
  case 't':
    print_time_per_line = 1;
    DEBUG(10) ("add the time to the output");
  break;
	case 'd':
	    if ((debug_level = atoi(optarg)) < 0) {
		debug_level = DEFAULT_DEBUG_LEVEL;
		DEBUG(1) ("warning: -d flag with 0 debug level '%s'", optarg);
	    }
	    break;
	case 'f':
	    if ((max_desired_fds = atoi(optarg)) < (NUM_RESERVED_FDS + 2)) {
		DEBUG(1) ("warning: -f flag must be used with argument >= %d",
			  NUM_RESERVED_FDS + 2);
		max_desired_fds = 0;
	    }
	    break;
	case 'h':
	    print_usage();
	    exit(0);
	    break;
	case 'i': device = optarg; break;
	case 'L': lockname = optarg; break;
	case 'o': outdir = optarg; break;
	case 'p':
	    no_promisc = 1;
	    DEBUG(10) ("NOT turning on promiscuous mode");
	    break;
	case 'r':
	    infile = optarg;
	    break;
	case 'v':
	    debug_level = 10;
	    break;
	case 'Z':
	    opt_Z = 1;
	    break;
	case 'e':
	    use_color  = 1;
	    DEBUG(10) ("using colors");
	    break;
	case 'X': xmlout = optarg;break;
	default:
	    DEBUG(1) ("error: unrecognized switch '%c'", optopt);
	    need_usage = 1;
	    break;
	}
    }

    /* print help and exit if there was an error in the arguments */
    if (need_usage) {
	print_usage();
	exit(1);
    }

    struct stat sbuf;
    if(lockname){
#if defined(HAVE_SEMAPHORE_H) && defined(HAVE_PTHREAD)
	semlock = sem_open(lockname,O_CREAT,0777,1); // get the semaphore
#else
	fprintf(stderr,"%s: attempt to create lock pthreads not present\n",argv[0]);
	exit(1);
#endif	
    }

    if(force_binary_output){
	strip_nonprint = false;
    }

    /* make sure outdir is a directory. If it isn't, try to make it.*/
    if(stat(outdir,&sbuf)==0){
	if(!S_ISDIR(sbuf.st_mode)){
	    die("outdir must be a directory: %s",outdir);
	}
    } else {
	if(mkdir(outdir,0777)){
	    die("Cannot create outdir %s",outdir);
	}
    }

    if(xmlout) dfxml_create(argc,argv,xmlout);

    argc -= optind;
    argv += optind;

    /* hello, world */
    DEBUG(10) ("%s version %s by Jeremy Elson <jelson@circlemud.org>",
	       PACKAGE, VERSION);

    if (infile != NULL) {
	/* Since we don't need network access, drop root privileges */
	setuid(getuid());

	/* open the capture file */
	if ((pd = pcap_open_offline(infile, error)) == NULL)
	    die("%s", error);

	/* get the handler for this kind of packets */
	dlt = pcap_datalink(pd);
	handler = find_handler(dlt, infile);
    } else {
	/* if the user didn't specify a device, try to find a reasonable one */
	if (device == NULL)
	    if ((device = pcap_lookupdev(error)) == NULL)
		die("%s", error);

	/* make sure we can open the device */
	if ((pd = pcap_open_live(device, SNAPLEN, !no_promisc, 1000, error)) == NULL)
	    die("%s", error);

	/* drop root privileges - we don't need them any more */
	setuid(getuid());

	/* get the handler for this kind of packets */
	dlt = pcap_datalink(pd);
	handler = find_handler(dlt, device);
    }

    /* get the user's expression out of remainder of the arg... */
    std::string expression = "";
    for(int i=0;i<argc;i++){
	if(expression.size()>0) expression+=" ";
	expression += argv[i];
    }

    /* add 'ip or vlan' to the user-specified filtering expression (if any) to
     * prevent non-ip packets from being delivered.
     */
    if (expression == "") {
	expression = DEFAULT_FILTER;
    }

    /* If DLT_NULL is "broken", giving *any* expression to the pcap
     * library when we are using a device of type DLT_NULL causes no
     * packets to be delivered.  In this case, we use no expression, and
     * print a warning message if there is a user-specified expression */
#ifdef DLT_NULL_BROKEN
    if (dlt == DLT_NULL && expression != ""){
	DEBUG(1)("warning: DLT_NULL (loopback device) is broken on your system;");
	DEBUG(1)("         filtering does not work.  Recording *all* packets.");
    }
#endif /* DLT_NULL_BROKEN */

    DEBUG(20) ("filter expression: '%s'",expression.c_str());

    /* install the filter expression in libpcap */
    if (pcap_compile(pd, &fcode, expression.c_str(), 1, 0) < 0){
	die("%s", pcap_geterr(pd));
    }

    if (pcap_setfilter(pd, &fcode) < 0){
	die("%s", pcap_geterr(pd));
    }

    /* initialize our flow state structures */
    init_tcpip();

    /* set up signal handlers for graceful exit (pcap uses onexit to put
     * interface back into non-promiscuous mode
     */
    portable_signal(SIGTERM, terminate);
    portable_signal(SIGINT, terminate);
    portable_signal(SIGHUP, terminate);

    /* start listening! */
    if (infile == NULL) DEBUG(1) ("listening on %s", device);
    if (pcap_loop(pd, -1, handler, NULL) < 0){
	die("%s", pcap_geterr(pd));
    }

    /* -1 causes pcap_loop to loop forever, but it finished when the input file is exhausted. */

    flow_close_all();

#if ENABLE_GZIP
    if(opt_Z==0){
	printf("Decompressing gzip files...\n");
    }
#endif

    if(xreport){
	xreport->add_rusage();
	xreport->pop();			// bulk_extractor
	xreport->close();
	delete xreport;		  // not strictly needed, but why not?
    }
    return 0;
}
