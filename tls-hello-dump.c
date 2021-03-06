/*
 * tls-hello-dump.c
 *
 * Copyright (C) 2016 xz_wei <azrlew@gmail.com>
 *
 ****************************************************************************
 *
 * This software is a modification of:
 *
 * TLS ClientHello/ServerHello Dumper (for XMPP).
 *
 * Version 0.5 (2013-11-06)
 * Copyright (C) 2013 Georg Lukas <georg@op-co.de>
 *
 ****************************************************************************
 *
 * This software is a modification of:
 *
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 * "sniffer.c" is distributed under these terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
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
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 *
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 *
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 *
 * The Ethernet size is always 14 bytes.
 *
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if
 * you're using structures, you must use structures where the members
 * always have the same size on all platforms, because the sizes of the
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by
 * the protocol specification, not by the way a particular platform's C
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after
 * the beginning of the packet data.  To find the TCP header, look
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 *
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip"
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end
 * of the captured data in the packet - you might, for example, have a
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too
 * small for an IP header.  The length of the captured data is given in
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than
 * the length of the packet, if you're capturing with a snapshot length
 * other than a value >= the maximum packet size.
 * <end of response>
 *
 ****************************************************************************
 *
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 *
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 *
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression           Description
 * ----------           -----------
 * ip                   Capture all IP packets.
 * tcp                  Capture only TCP packets.
 * tcp port 80          Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3     Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME        "tls-hello-dumper"
#define APP_DESC        "TLS ClientHello/ServerHello Dumper"
#define APP_COPYRIGHT   "Copyright (c) 2013 Georg Lukas, 2016 Wei, based on code by the Tcpdump Group."
#define APP_DISCLAIMER  "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "cipher_suites.h"
#include "inet_hashtable.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

u_char Human_Readable = 0;
u_char Suppress_Success = 0;
struct free_list *Free_List = NULL;
struct hashtable *Inet_HT = NULL;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

    printf("%s - %s\n", APP_NAME, APP_DESC);
    printf("%s\n", APP_COPYRIGHT);
    printf("%s\n", APP_DISCLAIMER);
    printf("\n");

    return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{
    printf("\nUsage: %s [-hb] [-p port/protocol] [-f filter] [device or pcap file]\n", APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    -s  Suppress successful handshake.\n");
    printf("    -h  Print human-readable cipher name rather than cipher id.\n");
    printf("    -b  Batch mode (no banner).\n");
    printf("    -p  Port or protocol.\n");
    printf("    -f  Customized filter.\n");

    return;
}

#define SSL2_VERSION 0x002
#define SSL_MIN_GOOD_VERSION    SSL2_VERSION
#define SSL_MAX_GOOD_VERSION    0x304    // let's be optimistic here!

#define TLS_ALERT        21
#define TLS_HANDSHAKE    22
#define SSL_HANDSHAKE    0x80
#define TLS_CLIENT_HELLO    1
#define TLS_SERVER_HELLO    2

#define OFFSET_HELLO_VERSION    9
#define SSL_OFFSET_HELLO_VERSION    3
#define OFFSET_SESSION_LENGTH    43
#define OFFSET_CIPHER_LIST    44
#define SSL_OFFSET_CIPHERSPEC_LENGTH    5
#define SSL_OFFSET_CIPHER_LIST    11
#define OFFSET_ALERT_LEVEL 5
#define OFFSET_ALERT_DESC  6

#define ALERT_LEVEL(x) (x==2?"FATAL":"WARN")

static inline char*
ssl_version(u_short version) {
    static char hex[7];
    switch (version) {
        case 0x002: return "SSLv2";
        case 0x300: return "SSLv3";
        case 0x301: return "TLSv1";
        case 0x302: return "TLSv1.1";
        case 0x303: return "TLSv1.2";
    }
    snprintf(hex, sizeof(hex), "0x%04hx", version);
    return hex;
}

/* ref: https://www.iana.org/assignments/tls-parameters/tls-parameters.txt */
static inline const char*
alert_msg(const u_char alert_desc) {
    static char hex[5];
    switch (alert_desc) {
        case 0  : return "close_notify";                    // [RFC5246]
        case 10 : return "unexpected_message";              // [RFC5246]
        case 20 : return "bad_record_mac";                  // [RFC5246]
        case 21 : return "decryption_failed";               // [RFC5246]
        case 22 : return "record_overflow";                 // [RFC5246]
        case 30 : return "decompression_failure";           // [RFC5246]
        case 40 : return "handshake_failure";               // [RFC5246]
        case 41 : return "no_certificate_RESERVED";         // [RFC5246]
        case 42 : return "bad_certificate";                 // [RFC5246]
        case 43 : return "unsupported_certificate";         // [RFC5246]
        case 44 : return "certificate_revoked";             // [RFC5246]
        case 45 : return "certificate_expired";             // [RFC5246]
        case 46 : return "certificate_unknown";             // [RFC5246]
        case 47 : return "illegal_parameter";               // [RFC5246]
        case 48 : return "unknown_ca";                      // [RFC5246]
        case 49 : return "access_denied";                   // [RFC5246]
        case 50 : return "decode_error";                    // [RFC5246]
        case 51 : return "decrypt_error";                   // [RFC5246]
        case 60 : return "export_restriction_RESERVED";     // [RFC5246]
        case 70 : return "protocol_version";                // [RFC5246]
        case 71 : return "insufficient_security";           // [RFC5246]
        case 80 : return "internal_error";                  // [RFC5246]
        case 86 : return "inappropriate_fallback";          // [RFC7507]
        case 90 : return "user_canceled";                   // [RFC5246]
        case 100: return "no_renegotiation";                // [RFC5246]
        case 110: return "unsupported_extension";           // [RFC5246]
        case 111: return "certificate_unobtainable";        // [RFC6066]
        case 112: return "unrecognized_name";               // [RFC6066]
        case 113: return "bad_certificate_status_response"; // [RFC6066]
        case 114: return "bad_certificate_hash_value";      // [RFC6066]
        case 115: return "unknown_psk_identity";            // [RFC4279]
    }
    snprintf(hex, sizeof(hex), "0x%02X", alert_desc);
    return hex;
}

void
print_cipher(const int cipher_id) {
    if (Human_Readable) {
        const char *cipher_name;
        cipher_name = get_readable_cipher_name(cipher_id, LEN(ssl_20_cipher_suites), ssl_20_cipher_suites);
        if (!cipher_name)
            cipher_name = get_readable_cipher_name(cipher_id, LEN(ssl_31_ciphersuite), ssl_31_ciphersuite);
        if (cipher_name) {
            printf(":%s", cipher_name);
            return;
        }
    }
    printf(":%06X", cipher_id);
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const u_char *payload;                  /* Packet payload */

    int size_ip;
    int size_iptotal;
    int size_tcp;
    int size_payload;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        // fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            break;
        case IPPROTO_UDP:
            fprintf(stderr, "Ignore UDP\n");
            return;
        case IPPROTO_ICMP:
            fprintf(stderr, "Ignore ICMP\n");
            return;
        case IPPROTO_IP:
            fprintf(stderr, "Ignore IP\n");
            return;
        default:
            fprintf(stderr, "%s\t%s\tProtocol UNKNOWN\n",
                    inet_ntoa(ip->ip_src),
                    inet_ntoa(ip->ip_dst));
            return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        // fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    u_int cs_id, cs_len, cs_offset;
    struct node *conn;
    if ((tcp->th_flags & (TH_FIN|TH_RST))) {
        /* socket is closing */
        u_char is_from_srv = 1;
        conn = ht_get(Inet_HT,
                ip->ip_dst.s_addr, ip->ip_src.s_addr,
                tcp->th_dport, tcp->th_sport);
        if (conn == NULL) {
            conn = ht_get(Inet_HT,
                    ip->ip_src.s_addr, ip->ip_dst.s_addr,
                    tcp->th_sport, tcp->th_dport);
            is_from_srv = 0;
        }
        if (conn == NULL)
            return;
        /* close too early */
        /* maybe rejected by server due to ssl version */
        printf("%s:%hu\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
        printf("%s:%hu\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
        printf("REJECT %s over %s ",
                ssl_version(conn->hello_version),
                ssl_version(conn->proto_version));
        if (conn->proto_version == SSL2_VERSION) {
            /* sslv2 */
            for (cs_id = 0; cs_id < conn->cipher_len; cs_id += 3)
                print_cipher(
                        (conn->ciphers[cs_id]<<16)  |
                        (conn->ciphers[cs_id+1]<<8) |
                         conn->ciphers[cs_id+2]);
        } else if (conn->proto_version > SSL2_VERSION) {
            /* tls */
            for (cs_id = 0; cs_id < conn->cipher_len; cs_id += 2)
                print_cipher((conn->ciphers[cs_id]<<8) |
                        conn->ciphers[cs_id+1]);
        }
        printf(":\n");

        ht_remove(Free_List, Inet_HT,
              is_from_srv? ip->ip_dst.s_addr : ip->ip_src.s_addr,
              is_from_srv? ip->ip_src.s_addr : ip->ip_dst.s_addr,
              is_from_srv? tcp->th_dport : tcp->th_sport,
              is_from_srv? tcp->th_sport : tcp->th_dport);

        return;
    }

    /* compute tcp payload (segment) size */
    size_iptotal = ntohs(ip->ip_len);
    if (size_iptotal == 0 || size_iptotal > header->caplen)
    {
        /* if TSO is used, ip_len is 0x0000 */
        /* only process up to caplen bytes. */
        size_iptotal = header->caplen;
    }
    size_payload = size_iptotal - (size_ip + size_tcp);

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    if (payload[0] == TLS_ALERT) {
        /* remove it from tracking table right after saw the alert */
        /* automatically avoid encrypted close notification (alert 0x0) */
        conn = ht_remove(Free_List, Inet_HT,
                ip->ip_src.s_addr, ip->ip_dst.s_addr,
                tcp->th_sport, tcp->th_dport);
        if (conn == NULL) {
            /* Either party may initiate a close by sending an alert. */
            conn = ht_remove(Free_List, Inet_HT,
                    ip->ip_dst.s_addr, ip->ip_src.s_addr,
                    tcp->th_dport, tcp->th_sport);
        }
        if (conn == NULL) {
            /* return since we do not saw the socket before */
            return;
        }

        if (size_payload <= OFFSET_ALERT_DESC) { // at least one cipher + compression
            fprintf(stderr, "%s:%hu\t%s:%hu\tTLS alert header too short: %d bytes\n",
                    inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
                    inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport),
                    size_payload);
            return;
        }

        printf("%s:%hu\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
        printf("%s:%hu\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

        u_short proto_version = payload[1]*256 + payload[2];
        u_char alert_level = payload[OFFSET_ALERT_LEVEL];
        u_char alert_desc = payload[OFFSET_ALERT_DESC];
        printf("%s Alert %s %s ",
                ssl_version(proto_version),
                ALERT_LEVEL(alert_level),
                alert_msg(alert_desc)
                );
        if (conn->proto_version == SSL2_VERSION) {
            /* sslv2 */
            for (cs_id = 0; cs_id < conn->cipher_len; cs_id += 3)
                print_cipher(
                        (conn->ciphers[cs_id]<<16)  |
                        (conn->ciphers[cs_id+1]<<8) |
                         conn->ciphers[cs_id+2]);
        } else if (conn->proto_version > SSL2_VERSION) {
            /* tls */
            for (cs_id = 0; cs_id < conn->cipher_len; cs_id += 2)
                print_cipher((conn->ciphers[cs_id]<<8) |
                        conn->ciphers[cs_id+1]);
        }
        printf(":\n");
    } else if (payload[0] == TLS_HANDSHAKE) {
        if (size_payload < OFFSET_CIPHER_LIST + 3) { // at least one cipher + compression
            fprintf(stderr, "%s:%hu\t%s:%hu\tTLS handshake header too short: %d bytes\n",
                    inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
                    inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport),
                    size_payload);
            return;
        }

        u_short proto_version = payload[1]*256 + payload[2];
        u_short hello_version = payload[OFFSET_HELLO_VERSION]*256 + payload[OFFSET_HELLO_VERSION+1];

        if (proto_version < SSL_MIN_GOOD_VERSION || proto_version >= SSL_MAX_GOOD_VERSION ||
                hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
            printf("%s:%hu\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("%s:%hu\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf("%s bad version(s)\n", ssl_version(hello_version));
            return;
        }

        // skip session ID
        const u_char *cipher_data = &payload[OFFSET_SESSION_LENGTH];
#ifdef LOG_SESSIONID
        if (cipher_data[0] != 0 && !Suppress_Success) {
            printf("SID[%hhu] ", cipher_data[0]);
        }
#endif
        if (size_payload < OFFSET_SESSION_LENGTH + cipher_data[0] + 3) {
            printf("%s:%hu\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("%s:%hu\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf("SessionID too long: %hhu bytes\n", cipher_data[0]);
            return;
        }
        cipher_data += 1 + cipher_data[0];

        if (!Suppress_Success) {
            printf("%s:%hu\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("%s:%hu\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf("%s ", ssl_version(proto_version));
        }

        switch (payload[5]) {
            case TLS_CLIENT_HELLO:
                cs_len = cipher_data[0]*256 + cipher_data[1];
                cipher_data += 2; // skip cipher suites length
                // FIXME: check for buffer overruns
                if (!Suppress_Success) {
                    printf("ClientHello %s ", ssl_version(hello_version));
                    for (cs_id = 0; cs_id < cs_len/2; cs_id++)
                        print_cipher((cipher_data[2*cs_id]<<8) | cipher_data[2*cs_id + 1]);
                    printf(":\n");
                }

                ht_insert(Free_List, Inet_HT,
                        ip->ip_src.s_addr, ip->ip_dst.s_addr,
                        tcp->th_sport, tcp->th_dport,
                        proto_version, hello_version,
                        cs_len, cipher_data);
                break;
            case TLS_SERVER_HELLO:
                if (!Suppress_Success) {
                    printf("ServerHello %s ", ssl_version(hello_version));
                    print_cipher((cipher_data[0]<<8) | cipher_data[1]);
                    printf(":\n");
                }

                ht_remove(Free_List, Inet_HT,
                        ip->ip_dst.s_addr, ip->ip_src.s_addr,
                        tcp->th_dport, tcp->th_sport);
                break;
            default:
                printf("Not a Hello\n");
                return;
        }

    } else if (payload[0] == SSL_HANDSHAKE && (payload[2] == TLS_CLIENT_HELLO)) {
        // SSL 2.0 client hello is supported even though SSL 2.0 is not supported
        if (size_payload <= SSL_OFFSET_CIPHERSPEC_LENGTH + 1) {
            fprintf(stderr, "%s:%hu\t%s:%hu\tSSLv2 handshake header too short: %d bytes\n",
                    inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
                    inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport),
                    size_payload);
            return;
        }
        cs_len = payload[SSL_OFFSET_CIPHERSPEC_LENGTH]*256 + payload[SSL_OFFSET_CIPHERSPEC_LENGTH+1];
        if (size_payload < SSL_OFFSET_CIPHER_LIST + cs_len) {
            fprintf(stderr, "%s:%hu\t%s:%hu\tSSLv2 handshake header too short: %d bytes\n",
                    inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
                    inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport),
                    size_payload);
            return;
        }
        u_short hello_version = payload[SSL_OFFSET_HELLO_VERSION]*256 + payload[SSL_OFFSET_HELLO_VERSION+1];
        if (hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
            printf("%s:%hu\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("%s:%hu\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf("%s bad version(s)\n", ssl_version(hello_version));
            return;
        }

        if (!Suppress_Success) {
            printf("%s:%hu\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("%s:%hu\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf("%s ClientHello %s", ssl_version(0x002), ssl_version(hello_version));
            for (cs_offset = SSL_OFFSET_CIPHER_LIST; cs_offset < SSL_OFFSET_CIPHER_LIST+cs_len; cs_offset+=3)
                print_cipher((payload[cs_offset]<<16) | (payload[cs_offset+1]<<8) | payload[cs_offset+2]);
            printf(":\n");
        }

        ht_insert(Free_List, Inet_HT,
                ip->ip_src.s_addr, ip->ip_dst.s_addr,
                tcp->th_sport, tcp->th_dport,
                0x0002, hello_version,
                cs_len, payload + SSL_OFFSET_CIPHER_LIST);
    }
}

// PCAP has no payload[offset] field, so we need to get the payload offset
// from the TCP header (offset 12, upper 4 bits, number of 4-byte words):
#define FILTER_TCPSIZE    "tcp[12]/16*4"

// TLS Handshake starts with a '22' byte, version, length,
// and then '01'/'02' for client/server hello
// And TLS Alert starts with a '21' byte, version, length.
#define FILTER_CLOSE "(tcp[tcpflags] & (tcp-rst|tcp-fin) != 0)"
#define FILTER_TLS_ALERT "(tcp[" FILTER_TCPSIZE "]=21)"
#define FILTER_TLS_HELLO "(tcp[" FILTER_TCPSIZE "]=22 and " \
    "(tcp[" FILTER_TCPSIZE "+5]=1 or tcp[" FILTER_TCPSIZE "+5]=2))"
#define FILTER_SSL_HELLO "(tcp[" FILTER_TCPSIZE "]=128 and tcp[" FILTER_TCPSIZE "+2]=1)"

#define FILTER_TLS "( "     \
    FILTER_CLOSE " or "     \
    FILTER_TLS_ALERT " or " \
    FILTER_TLS_HELLO " or " \
    FILTER_SSL_HELLO " )"

char *filter_https = "tcp port 443 and " FILTER_TLS;
char *filter_xmpp = "(tcp port 5222 or tcp port 5223 or tcp port 5269) and " FILTER_TLS;
char *filter_format = "tcp port %-5hu and " FILTER_TLS; // strlen("%-5hu")==5, enough to fit port

int main(int argc, char **argv)
{

    char *dev = NULL;              /* capture device name */
    int dev_is_file = 0;           /* capture from a file, not from the network */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    pcap_t *handle;                /* packet capture handle */

    /* filter expression [3]: port 5222, TLS Handshake, ClientHello/ServerHello */
    char *filter_exp = filter_https;
    uint16_t filter_port;
    struct bpf_program fp;  /* compiled filter program (expression) */
    bpf_u_int32 mask;       /* subnet mask */
    bpf_u_int32 net;        /* ip */

    /* Make sure pipe sees new packets unbuffered. */
    setvbuf(stdout, (char *)NULL, _IOLBF, 0);

    u_char batch_mode = 0;
    int opt;
    while ((opt = getopt(argc, argv, "shbp:f:")) != -1) {
        switch (opt) {
            case 's': Suppress_Success = 1; break;
            case 'h': Human_Readable = 1; break;
            case 'b': batch_mode = 1; break;
            case 'p':
                      if (strcmp(optarg, "https") == 0) {
                          filter_exp = filter_https;
                      } else if (strcmp(optarg, "xmpp") == 0) {
                          filter_exp = filter_xmpp;
                      } else if (sscanf(optarg, "%hu", &filter_port) == 1) {
                          /* HACK: filter_format is long enough to fit formatted string */
                          filter_exp = strdup(filter_format);
                          sprintf(filter_exp, filter_format, filter_port);
                      }
                      break;
            case 'f':
                      filter_exp = optarg;
                      break;
            default:
                      print_app_usage();
                      exit(EXIT_FAILURE);
        }
    }
    if (optind < argc) {
        dev = argv[optind];
    } else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    if (!batch_mode) print_app_banner();

    /* Prepare hash table */
    /* TODO: read size opts from args */
    Free_List = fl_init(DEFAULT_INIT_SIZE, DEFAULT_MAX_SIZE);
    if (Free_List == NULL) {
        fprintf(stderr, "Couldn't init memory pool with size %u\n",
                DEFAULT_INIT_SIZE);
        exit(EXIT_FAILURE);
    }
    Inet_HT = ht_init(DEFAULT_HASH_TABLE_SIZE);
    if (Inet_HT == NULL) {
        fprintf(stderr, "Couldn't init hash table with size %u\n",
                DEFAULT_HASH_TABLE_SIZE);
        exit(EXIT_FAILURE);
    }

    /* try to open capture "device" as a file, if it fails */
    /* get network number and mask associated with capture device */
    if (access(dev, R_OK) != -1) {
        dev_is_file = 1;
    } else
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
            net = 0;
            mask = 0;
        }

    /* print capture info */
    if (!batch_mode) {
        printf("Source: %s\n", dev);
        printf("Filter expression: %s\n", filter_exp);
        printf("\n");
    }
    if (!batch_mode) printf("Source\t\tDestination\t");
    if (!batch_mode) printf("Packet content\n");

    /* open capture device */
    if (dev_is_file)
        handle = pcap_open_offline(dev, errbuf);
    else
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open source %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    if (!batch_mode) printf("\nCapture complete.\n");

    return 0;
}

