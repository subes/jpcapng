/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#) $Header: /usr/cvsroot/wpdpack/Include/PCAP.H,v 1.9 2003/02/04 14:17:40 varenni Exp $ (LBL)
 */

#ifndef lib_pcap_h
#define lib_pcap_h

#ifdef WIN32
#include <pcap-stdinc.h>
#else /* WIN32 */
#include <sys/types.h>
#include <sys/time.h>
#endif /* WIN32 */

#include <net/bpf.h>

#include <stdio.h>

#ifdef REMOTE
	#ifndef SOCKET
		#ifdef WIN32
			#define SOCKET unsigned int
		#else
			#define SOCKET int
		#endif
	#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define PCAP_ERRBUF_SIZE 256

/*
 * Compatibility for systems that have a bpf.h that
 * predates the bpf typedefs for 64-bit support.
 */
#if BPF_RELEASE - 0 < 199406
typedef	int bpf_int32;
typedef	u_int bpf_u_int32;
#endif

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;

/*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 *
 * Do not change the layout of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure).
 *
 * Also, do not change the interpretation of any of the members of this
 * structure, in any way (this includes using values other than
 * LINKTYPE_ values, as defined in "savefile.c", in the "linktype"
 * field).
 *
 * Instead:
 *
 *	introduce a new structure for the new format, if the layout
 *	of the structure changed;
 *
 *	send mail to "tcpdump-workers@tcpdump.org", requesting a new
 *	magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed file
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old file header as well as files with the new file header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes to "patches@tcpdump.org", so that future
 * versions of libpcap and programs that use it (such as tcpdump) will
 * be able to read your new capture file format.
 */
struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};

/*
 * As returned by the pcap_stats()
 */
struct pcap_stat {
	u_int ps_recv;		/* number of packets received */
	u_int ps_drop;		/* number of packets dropped */
	u_int ps_ifdrop;	/* drops by interface XXX not yet supported */
#ifdef REMOTE
#ifdef WIN32
//	u_int bs_capt;		/* number of packets that reach the application */
#endif /* WIN32 */
	u_int ps_capt;		/* number of packets that reach the application; please get rid off the Win32 ifdef */
	u_int ps_sent;		/* number of packets sent by the server on the network */
	u_int ps_netdrop;	/* number of packets lost on the network */
#endif
};

/*
 * Item in a list of interfaces.
 */
struct pcap_if {
	struct pcap_if *next;
	char *name;		/* name to hand to "pcap_open_live()" */
	char *description;	/* textual description of interface, or NULL */
	struct pcap_addr *addresses;
	bpf_u_int32 flags;	/* PCAP_IF_ interface flags */
};

#define PCAP_IF_LOOPBACK	0x00000001	/* interface is loopback */

/*
 * Representation of an interface address.
 */
struct pcap_addr {
	struct pcap_addr *next;
	struct sockaddr *addr;		/* address */
	struct sockaddr *netmask;	/* netmask for that address */
	struct sockaddr *broadaddr;	/* broadcast address for that address */
	struct sockaddr *dstaddr;	/* P2P destination address for that address */
};

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
			     const u_char *);

char	*pcap_lookupdev(char *);
int	pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);
pcap_t	*pcap_open_live(const char *, int, int, int, char *);
pcap_t	*pcap_open_dead(int, int);
pcap_t	*pcap_open_offline(const char *, char *);
void	pcap_close(pcap_t *);
int	pcap_loop(pcap_t *, int, pcap_handler, u_char *);
int	pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);
const u_char*
	pcap_next(pcap_t *, struct pcap_pkthdr *);
int	pcap_stats(pcap_t *, struct pcap_stat *);
int	pcap_setfilter(pcap_t *, struct bpf_program *);
int	pcap_getnonblock(pcap_t *, char *);
int	pcap_setnonblock(pcap_t *, int, char *);
void	pcap_perror(pcap_t *, char *);
char	*pcap_strerror(int);
char	*pcap_geterr(pcap_t *);
int	pcap_compile(pcap_t *, struct bpf_program *, char *, int,
	    bpf_u_int32);
int	pcap_compile_nopcap(int, int, struct bpf_program *,
	    char *, int, bpf_u_int32);
void	pcap_freecode(struct bpf_program *);
int	pcap_datalink(pcap_t *);
int	pcap_list_datalinks(pcap_t *, int **);
int	pcap_set_datalink(pcap_t *, int);
int	pcap_datalink_name_to_val(const char *);
const char *pcap_datalink_val_to_name(int);
int	pcap_snapshot(pcap_t *);
int	pcap_is_swapped(pcap_t *);
int	pcap_major_version(pcap_t *);
int	pcap_minor_version(pcap_t *);

/* XXX */
FILE	*pcap_file(pcap_t *);
int	pcap_fileno(pcap_t *);

pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
int	pcap_dump_flush(pcap_dumper_t *);
void	pcap_dump_close(pcap_dumper_t *);
void	pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);

int	pcap_findalldevs(pcap_if_t **, char *);
void	pcap_freealldevs(pcap_if_t *);

/* XXX this guy lives in the bpf tree */
u_int	bpf_filter(struct bpf_insn *, u_char *, u_int, u_int);
int	bpf_validate(struct bpf_insn *f, int len);
char	*bpf_image(struct bpf_insn *, int);
void	bpf_dump(struct bpf_program *, int);

#ifdef WIN32
/*
 * Win32 definitions
 */

int pcap_setbuff(pcap_t *p, int dim);
int pcap_setmode(pcap_t *p, int mode);
int pcap_sendpacket(pcap_t *p, u_char *buf, int size);
int pcap_setmintocopy(pcap_t *p, int size);

#ifdef WPCAP
/* Include file with the wpcap-specific extensions */
#include <Win32-Extensions.h>
#endif

#define MODE_CAPT 0
#define MODE_STAT 1
#define MODE_MON 2

#endif /* WIN32 */

#ifdef REMOTE
/* Include all new definitions (structures and functions like pcap_open() */
/* This is no really a remote feature, but, rigth now, it is included like that */

/*! \defgroup PubGroup WinPcap exported functions and structures */
/*! \defgroup PriGroup WinPcap internal functions and structures */







/*! \ingroup PubGroup
	\brief Defines the maximum buffer size in which address, port, interface names are kept.

	In case the adapter name or such is larger than this value, it is truncated.
	This is not used by the user; however it must be aware that an hostname / interface
	name longer than this value will be truncated.
*/
#define PCAP_BUF_SIZE 1024



/*! \ingroup PubGroup
	\brief Internal representation of the type of source in use (null, file, 
	remote/local interface).

	This indicates a file, i.e. the user want to open a capture from a local file.
*/
#define PCAP_SRC_FILE 2
/*! \ingroup PubGroup
	\brief Internal representation of the type of source in use (null, file, 
	remote/local interface).

	This indicates a local interface, i.e. the user want to open a capture from 
	a local interface. This does not involve the RPCAP protocol.
*/
#define PCAP_SRC_IFLOCAL 3
/*! \ingroup PubGroup
	\brief Internal representation of the type of source in use (null, file, 
	remote/local interface).

	This indicates a remote interface, i.e. the user want to open a capture from 
	an interface on a remote host. This does involve the RPCAP protocol.
*/
#define PCAP_SRC_IFREMOTE 4




/*! \ingroup PubGroup
	\brief String that will be used to determine the type of source in use (null, file,
	remote/local interface).

	This string will be prepended to the interface name in order to create a string
	that contains all the information required to open the source.

	This string indicates that the user wants to open a capture from a local file.
*/
#define PCAP_SRC_FILE_KEY "file://"
/*! \ingroup PubGroup
	\brief String that will be used to determine the type of source in use (null, file,
	remote/local interface).

	This string will be prepended to the interface name in order to create a string
	that contains all the information required to open the source.

	This string indicates that the user wants to open a capture from a network interface.
	This string does not necessarily involve the use of the RPCAP protocol. If the
	interface required resides on the local host, the RPCAP protocol is not involved
	and the local functions are used.
*/
#define PCAP_SRC_IF_KEY "rpcap://"






// definitions needed by the new pcap_open()
#define PCAP_OPENFLAG_PROMISCUOUS		1	/*!< pcap_open(): selects promiscuous mode */
#define PCAP_OPENFLAG_SERVEROPEN_DP		2	/*!< pcap_open(): selects who has to open the data connection(remote capture) */
#define PCAP_OPENFLAG_UDP_DP			4	/*!< pcap_open(): selects if the data connection has to be on top of UDP */





/*!	\ingroup PubGroup

	\brief This structure keeps the information needed to autheticate
	the user on a remote machine.
	
	The remote machine can either grant or refuse the access according 
	to the information provided.
	In case the NULL authentication is required, both 'username' and
	'password' can be NULL pointers.
	
	This structure is meaningless if the source is not a remote interface;
	in that case, the functions which requires such a structure can accept
	a NULL pointer as well.
*/
struct pcap_rmtauth
{
	/*!
		\brief Type of the authentication required.

		In order to provide maximum flexibility, we can support different types
		of authentication based on the value of this 'type' variable. The currently 
		supported authentication mathods are:
		- RPCAP_RMTAUTH_NULL: if the user does not provide an authentication method
		(this could enough if, for example, the RPCAP daemon allows connections 
		from trusted hosts only)
		- RPCAP_RMTAUTH_PWD: if the user is willing to provide a valid 
		username/password to authenticate itself on the remote machine. Username/
		password must be valid on the remote machine.

	*/
	int type;
	/*!
		\brief Zero-terminated string containing the username that has to be 
		used on the remote machine for authentication.
		
		This field is meaningless in case of the RPCAP_RMTAUTH_NULL authentication
		and it can be NULL.
	*/
	char *username;
	/*!
		\brief Zero-terminated string containing the password that has to be 
		used on the remote machine for authentication.
		
		This field is meaningless in case of the RPCAP_RMTAUTH_NULL authentication
		and it can be NULL.
	*/
	char *password;
};



/*! \ingroup PubGroup
	\brief It defines the NULL authentication.

	This value has to be used within the 'type' member of the pcap_rmtauth structure.
	The 'NULL' authentication has to be equal to 'zero', so that old applications
	can just put every field of struct pcap_rmtauth to zero, and it does work.
*/
#define RPCAP_RMTAUTH_NULL 0
/*! \ingroup PubGroup
	\brief It defines the username/password authentication.

	With this type of authentication, the RPCAP protocol will use the username/
	password provided to authenticate the user on the remote machine. If the
	authentication is successful (and the user has the right to open network devices)
	the RPCAP connection will continue; otherwise it will be dropped.

	This value has to be used within the 'type' member of the pcap_rmtauth structure.
*/
#define RPCAP_RMTAUTH_PWD 1


#define RPCAP_HOSTLIST_SIZE 1024	/*!< Maximum lenght of an host name (needed for the RPCAP active mode) */


// Exported functions
pcap_t *pcap_open(char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf);
int pcap_createsrcstr(char *source, int type, const char *host, const char *port, const char *name, char *errbuf);
int pcap_parsesrcstr(const char *source, int *type, char *host, char *port, char *name, char *errbuf);
int pcap_findalldevs_ex(char *host, char *port, SOCKET sockctrl, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);
int pcap_remoteact_accept(const char *address, const char *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth, char *errbuf);
int pcap_remoteact_list(char *hostlist, char sep, int size, char *errbuf);
int pcap_remoteact_close(const char *host, char *errbuf);
void pcap_remoteact_cleanup();
#endif


#if (defined(HAVE_PCAPREADEX) || defined(WIN32))
int pcap_read_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, u_char **pkt_data);
#endif


#ifdef __cplusplus
}
#endif

#endif
