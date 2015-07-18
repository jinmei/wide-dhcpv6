/*	$KAME: auth.h,v 1.3 2004/09/07 05:03:02 jinmei Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __AUTH_H
#define __AUTH_H 1

#include <sys/types.h>
#include <sys/queue.h>

#include <dhcp6.h>

#ifdef __sun__
#define	__P(x)	x
#ifndef	U_INT32_T_DEFINED
#define	U_INT32_T_DEFINED
typedef uint32_t u_int32_t;
#endif
#endif

#define MD5_DIGESTLENGTH 16

/* secret key information for delayed authentication */
struct keyinfo {
	struct keyinfo *next;

	char *name;		/* key name */

	char *realm;		/* DHCP realm */
	size_t realmlen;	/* length of realm */
	u_int32_t keyid;	/* key ID */
	unsigned char *secret;	/* binary key */
	size_t secretlen;	/* length of the key */
	time_t expire;		/* expiration time (0 means forever) */
};

struct auth_peer {
	TAILQ_ENTRY(auth_peer) link;
	struct duid id;
	struct dhcp6_vbuf pubkey;
	struct timeval ts_last;
	struct timeval ts_rcv_last;
};
TAILQ_HEAD(dhcp6_auth_peerlist, auth_peer);

extern int dhcp6_validate_key __P((struct keyinfo *));
extern int dhcp6_calc_mac __P((unsigned char *, size_t, int, int, size_t,
    struct keyinfo *));
extern int dhcp6_verify_mac __P((unsigned char *, ssize_t, int, int, size_t,
    struct keyinfo *));

int dhcp6_auth_init __P((void));
int dhcp6_read_pubkey __P((int, const char *, void **));
int dhcp6_read_privkey __P((int, const char *, void **));
int dhcp6_read_certificate __P((const char *, void **));
void dhcp6_free_pubkey __P((void **));
void dhcp6_free_certificate __P((void **));
void dhcp6_free_privkey __P((int, void **));

void dhcp6_set_pubkey __P((void *, struct dhcp6_vbuf *));
void dhcp6_set_certificate __P((void *, struct dhcp6_vbuf *));
void *dhcp6_copy_pubkey __P((void *));
void *dhcp6_copy_certificate __P((void *));
void *dhcp6_copy_privkey __P((int, void *));
size_t dhcp6_get_sigsize __P((int, void *));
struct authparam;
int dhcp6_sign_msg __P((unsigned char *, size_t, size_t, struct authparam *));
int dhcp6_verify_msg __P((unsigned char *, size_t, size_t, size_t, int, int,
			  const struct dhcp6_vbuf *pubkey));
struct auth_peer *dhcp6_create_authpeer __P((const struct duid *,
					     const struct dhcp6_vbuf *));
struct auth_peer *
dhcp6_find_authpeer __P((const struct dhcp6_auth_peerlist *peers,
			 const struct duid *peer_id));
int dhcp6_check_timestamp __P((struct auth_peer *, const struct timeval *));
#endif
