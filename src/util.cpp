/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Id: util.c,v 1.9 2001/08/08 19:39:40 jelson Exp $
 *
 * $Log: util.c,v $
 * Revision 1.9  2001/08/08 19:39:40  jelson
 * ARGH!  These are changes that made up tcpflow 0.20, which for some reason I
 * did not check into the repository until now.  (Which of couse means
 * I never tagged v0.20.... argh.)
 *
 * Changes include:
 *
 *   -- portable signal handlers now used to do proper termination
 *
 *   -- patch to allow tcpflow to read from tcpdump stored captures
 *
 * Revision 1.8  1999/04/14 03:02:39  jelson
 * added typecasts for portability
 *
 * Revision 1.7  1999/04/13 01:38:16  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

#include "tcpflow.h"

static char *debug_prefix = NULL;
extern int max_desired_fds;

#define BUFSIZE 1024


/*************************************************************************/



/*
 * Remember our program name and process ID so we can use them later
 * for printing debug messages
 */
void init_debug(char *argv[])
{
    debug_prefix = (char *)calloc(sizeof(char), strlen(argv[0]) + 16);
    if(debug_prefix==0) die("malloc failed");
    sprintf(debug_prefix, "%s[%d]", argv[0], (int) getpid());
}


/*
 * Print a debugging message, given a va_list
 */
void print_debug_message(const char *fmt, va_list ap)
{
    /* print debug prefix */
    fprintf(stderr, "%s: ", debug_prefix);

    /* print the var-arg buffer passed to us */
    vfprintf(stderr, fmt, ap);

    /* add newline */
    fprintf(stderr, "\n");
    (void) fflush(stderr);
}

/* Print a debugging or informational message */
void debug_real(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_debug_message(fmt, ap);
    va_end(ap);
}
  

/* Print a debugging or informatioal message, then exit  */
void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_debug_message(fmt, ap);
    exit(1);
}

/* Try to find the maximum number of FDs this system can have open */
int get_max_fds(void)
{
    int max_descs = 0;
    const char *method;

    /* Use OPEN_MAX if it is available */
#if defined (OPEN_MAX)
    method = "OPEN_MAX";
    max_descs = OPEN_MAX;
#elif defined(RLIMIT_NOFILE)
    {
	struct rlimit limit;
	memset(&limit,0,sizeof(limit));

	method = "rlimit";
	if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
	    perror("getrlimit");
	    exit(1);
	}

	/* set the current to the maximum or specified value */
	if (max_desired_fds) limit.rlim_cur = max_desired_fds;
	else limit.rlim_cur = limit.rlim_max;

	if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
	    perror("setrlimit");
	    exit(1);
	}
	max_descs = limit.rlim_max;

#ifdef RLIM_INFINITY
	if (limit.rlim_max == RLIM_INFINITY) max_descs = MAX_FD_GUESS * 4;	/* pick a more reasonable max */
#endif
    }
#elif defined (_SC_OPEN_MAX)
    /* Okay, you don't have getrlimit() and you don't have OPEN_MAX.
     * Time to try the POSIX sysconf() function.  (See Stevens'
     * _Advanced Programming in the UNIX Environment_).  */
    method = "POSIX sysconf";
    errno = 0;
    if ((max_descs = sysconf(_SC_OPEN_MAX)) < 0) {
	if (errno == 0)
	    max_descs = MAX_FD_GUESS * 4;
	else {
	    perror("calling sysconf");
	    exit(1);
	}
    }

    /* if everything has failed, we'll just take a guess */
#else
    method = "random guess";
    max_descs = MAX_FD_GUESS;
#endif

    /* this must go here, after rlimit code */
    if (max_desired_fds) {
	DEBUG(10) ("using only %d FDs", max_desired_fds);
	return max_desired_fds;
    }

    DEBUG(10) ("found max FDs to be %d using %s", max_descs, method);
    return max_descs;
}


/* An attempt at making signal() portable.
 *
 * If we detect sigaction, use that; 
 * otherwise if we have setsig, use that;
 * otherwise, cross our fingers and hope for the best using plain old signal().
 *
 * Our first choice is sigaction (sigaction() is POSIX; signal() is
 * not.)  Taken from Stevens' _Advanced Programming in the UNIX Environment_.
 *
 * 10/6/08 - slg - removed RETSIGTYPE, since it hasn't been needed to 15 years
 */
void (*portable_signal(int signo, void (*func)(int)))(int)
{
#if defined(HAVE_SIGACTION)
    struct sigaction act, oact;

    memset(&act, 0, sizeof(act));
    memset(&oact, 0, sizeof(oact));
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(signo, &act, &oact) < 0) return (SIG_ERR);
    return (oact.sa_handler);
#elif defined(HAVE_SIGSET)
    return sigset(signo, func);
#else
    return signal(signo, func);
#endif /* HAVE_SIGACTION, HAVE_SIGSET */
}
