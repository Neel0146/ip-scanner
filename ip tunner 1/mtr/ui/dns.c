/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/*
    Non-blocking DNS portion --
    Copyright (C) 1998 by Simon Kirby <sim@neato.org>
    Released under GPL, as above.
*/

#include "config.h"

#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "mtr.h"
#include "dns.h"
#include "net.h"
#include "utils.h"
#include "packet/sockaddr.h"

struct dns_results {
    ip_t ip;
    char *name;
    struct dns_results *next;
};

static struct dns_results *results;

char *strlongip(
    sa_family_t family,
    ip_t * ip)
{
#ifdef ENABLE_IPV6
    static char addrstr[INET6_ADDRSTRLEN];

    return (char *) inet_ntop(family, ip, addrstr, sizeof addrstr);
#else
    return inet_ntoa(*ip);
#endif
}


#ifdef ENABLE_IPV6
#define UNUSED_IF_NO_IPV6       /* empty */
#else
#define UNUSED_IF_NO_IPV6 ATTRIBUTE_UNUSED
#endif

static int todns[2], fromdns[2];
static FILE *fromdnsfp;

static int longipstr(
    char *s,
    ip_t * dst,
    int family UNUSED_IF_NO_IPV6)
{
#ifdef ENABLE_IPV6
    return inet_pton(family, s, dst);
#else
    return inet_aton(s, dst);
#endif
}


static struct dns_results *findip(
    struct mtr_ctl *ctl,
    ip_t * ip)
{
    struct dns_results *t;

    for (t = results; t; t = t->next) {
        if (addrcmp(ip, &t->ip, ctl->af) == 0)
            return t;
    }

    return NULL;
}

static void set_sockaddr_ip(
    sa_family_t family,
    struct sockaddr_storage *sa,
    ip_t * ip)
{
    memset(sa, 0, sizeof(struct sockaddr_storage));
    sa->ss_family = family;
    memcpy(sockaddr_addr_offset(sa), ip, sockaddr_addr_size(sa));
}

void dns_open(
    void)
{
    int pid;

    if (pipe(todns) < 0) {
        error(EXIT_FAILURE, errno, "can't make a pipe for DNS process");
    }

    if (pipe(fromdns) < 0) {
        error(EXIT_FAILURE, errno, "can't make a pipe for DNS process");
    }
    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        error(EXIT_FAILURE, errno, "can't fork for DNS process");
    }
    if (pid == 0) {
        char buf[2048];
        int i;
        FILE *infp;

        /* Automatically reap children. */
        if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
            error(EXIT_FAILURE, errno, "signal");
        }

        /* Close all unnecessary FDs.
           for debugging and error reporting, keep std-in/out/err. */
        for (i = 3; i < fromdns[1]; i++) {
            if (i == todns[0])
                continue;
            if (i == fromdns[1])
                continue;
            close(i);
        }
        infp = fdopen(todns[0], "r");

        while (fgets(buf, sizeof(buf), infp)) {
            ip_t host;
            struct sockaddr_storage sa;
            socklen_t salen;
            char hostname[NI_MAXHOST];
            char result[INET6_ADDRSTRLEN + NI_MAXHOST + 2];

            if (!fork()) {
                int rv;

                buf[strlen(buf) - 1] = 0;       /* chomp newline. */

                sa_family_t family = (buf[0] == '4') ? AF_INET : AF_INET6;
                longipstr(buf +1, &host, family);
                set_sockaddr_ip(family, &sa, &host);
                salen = (family == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6);

                rv = getnameinfo((struct sockaddr *) &sa, salen,
                                 hostname, sizeof(hostname), NULL, 0, 0);
                if (rv == 0) {
                    snprintf(result, sizeof(result),
                             "%s %s\n", strlongip(family, &host), hostname);

                    rv = write(fromdns[1], result, strlen(result));
                    if (rv < 0)
                        error(0, errno, "write DNS lookup result");
                }

                exit(EXIT_SUCCESS);
            }
        }
        exit(EXIT_SUCCESS);
    } else {
        int flags;

        /* the parent. */
        close(todns[0]);        /* close the pipe ends we don't need. */
        close(fromdns[1]);
        fromdnsfp = fdopen(fromdns[0], "r");
        flags = fcntl(fromdns[0], F_GETFL, 0);
        flags |= O_NONBLOCK;
        fcntl(fromdns[0], F_SETFL, flags);
    }
}

int dns_waitfd(
    void)
{
    return fromdns[0];
}


void dns_ack(
    struct mtr_ctl *ctl)
{
    char buf[2048], host[NI_MAXHOST], name[NI_MAXHOST];
    ip_t hostip;
    struct dns_results *r;

    while (fgets(buf, sizeof(buf), fromdnsfp)) {
        sscanf(buf, "%s %s", host, name);

        longipstr(host, &hostip, ctl->af);
        r = findip(ctl, &hostip);
        if (r)
            r->name = xstrdup(name);
        else
            error(0, 0, "dns_ack: Couldn't find host %s", host);
    }
}



#ifdef ENABLE_IPV6

int dns_waitfd6(
    void)
{
    return -1;
}

void dns_ack6(
    void)
{
    return;
}

#endif


char *dns_lookup2(
    struct mtr_ctl *ctl,
    ip_t * ip)
{
    struct dns_results *r;
    char buf[INET6_ADDRSTRLEN + 2]; // af_byte + addr + null
    int rv;

    r = findip(ctl, ip);
    if (r) {
        /* we've got a result. */
        if (r->name)
            return r->name;
    } else {
        r = xmalloc(sizeof(struct dns_results));
        memcpy(&r->ip, ip, sizeof(r->ip));
        r->name = NULL;
        r->next = results;
        results = r;
        char ip4or6 = (ctl->af == AF_INET) ? '4' : '6';
        snprintf(buf, sizeof(buf), "%c%s\n", ip4or6, strlongip(ctl->af, ip));
        rv = write(todns[1], buf, strlen(buf));
        if (rv < 0)
            error(0, errno, "couldn't write to resolver process");
    }
    return NULL;
}


char *dns_lookup(
    struct mtr_ctl *ctl,
    ip_t * ip)
{
    char *t;

    if (!ctl->dns || !ctl->use_dns)
        return NULL;
    t = dns_lookup2(ctl, ip);
    return t ? t : strlongip(ctl->af, ip);
}

/* XXX check if necessary/exported. */

/* Resolve an IP address to a hostname. */
struct hostent *addr2host(
    const char *addr,
    int family)
{
    int len = 0;
    switch (family) {
    case AF_INET:
        len = sizeof(struct in_addr);
        break;
#ifdef ENABLE_IPV6
    case AF_INET6:
        len = sizeof(struct in6_addr);
        break;
#endif
    }
    return gethostbyaddr(addr, len, family);
}
