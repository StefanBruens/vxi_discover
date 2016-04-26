/*
 * Copyright 2016 Stefan Brüns <stefan.bruens@rwth-aachen.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#define _GNU_SOURCE
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_prot.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <assert.h>

/* from VXI-11 specification */
#define DEVICE_CORE 0x0607AF
#define DEVICE_CORE_VERSION 1

/* from RPC specification (RFC1832) */
#define PROTO_TCP 6

void fill_getport_xdr(XDR* xdr, uint32_t prog, uint32_t version, uint32_t proto)
{
    static uint32_t xid = 0; // random number
    uint32_t dummy = 0;
    xid++;

    struct call_body callb = {
        2, // RPC version
        PMAPPROG,
        PMAPVERS,
        PMAPPROC_GETPORT,
        _null_auth,
        _null_auth,
    };
    struct rpc_msg msg = {
        xid,
        CALL,
        callb,
    };

    assert(xdr_getpos(xdr) == 0);
    // push message header and call body
    xdr_callmsg(xdr, &msg);
    assert(xdr_getpos(xdr) == 4*10);

    // push GETPORT parameters
    xdr_int(xdr, &prog);
    xdr_int(xdr, &version);
    xdr_int(xdr, &proto);
    xdr_int(xdr, &dummy);

    assert(xdr_getpos(xdr) == 4*14);

}

void fill_vxi_getport_xdr(XDR* xdr)
{
    fill_getport_xdr(xdr, DEVICE_CORE, DEVICE_CORE_VERSION, PROTO_TCP);
}

short parse_getport_response(char* buf, size_t len)
{
    XDR xdr;
    xdrmem_create(&xdr, buf, len, XDR_DECODE);

    struct rpc_msg msg;
    msg.acpted_rply.ar_results.where = 0;
    msg.acpted_rply.ar_results.proc = (xdrproc_t)(xdr_void);
    // pull message header
    xdr_replymsg(&xdr, &msg);

    assert(msg.rm_direction == REPLY);
    assert(msg.rm_reply.rp_stat == MSG_ACCEPTED);

    int port;
    xdr_int(&xdr, &port);

    return (short)(port);
}

#if 0
assemble broadcast query for VXI
    XID: variable
    Type: CALL (0)
    RPC Version: 2
    Programm: Portmap (100000)
    ProgVersion: 2
    # Proc: CALLIT (5)
    Proc: GETPORT (3)
    CRED:
        AUTH_NULL (0)
        Len: 0
    Verifier:
        AUTH_NULL (0)
        Len: 0
    GETPORT Parameters:
        Programm: variable
        ProgVersion: variable
        Proto: TCP (6)
        Port: 0 (unused)

reply:
    XID: variable (same as above)
    Type: REPLY (1)
    State: accepted (0)
    Verifier:
        AUTH_NULL (0)
        Len: 0
    Accept state: RPC executed successfully (0)
    GETPORT Response:
        Port: variable

#endif

int main(int argc, char* argv[])
{
    struct sockaddr_in sock = {
        AF_INET, 111, 0 };

    if ((argc == 2) && (*argv[1] != '-')) {
        fprintf(stderr, "Sending unicast query to '%s'\n", argv[1]);
        if (inet_aton(argv[1], &sock.sin_addr) == 0) {
            fprintf(stderr, "Invalid address\n");
            exit(EXIT_FAILURE);
        }

        short port = pmap_getport(&sock,
            DEVICE_CORE, DEVICE_CORE_VERSION, IPPROTO_TCP);

        if (port) {
            fprintf(stderr, "Found VXI-11 on port %d\n", port);
        } else {
            fprintf(stderr, "RPC failed:\n%s\n",
                clnt_spcreateerror(""));
        }
        exit(0);
    }
    if ((argc == 2) && (*argv[1] == '-')) {
        if (strcmp(argv[1], "-b") != 0)
            exit(EXIT_FAILURE);

        int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        int udp_socket6 = socket(AF_INET6, SOCK_DGRAM, 0);
        int one = 1;
        setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
        setsockopt(udp_socket6, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

        setsockopt(udp_socket, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        setsockopt(udp_socket6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));

        XDR xdr;
        char buf[200];
        xdrmem_create(&xdr, buf, sizeof(buf), XDR_ENCODE);
        assert(xdr_getpos(&xdr) == 0);

        fill_vxi_getport_xdr(&xdr);

        struct ifaddrs *ifap, *ifp;
        if (getifaddrs(&ifap) != 0)
            exit(EXIT_FAILURE);

        struct sockaddr_storage address;
        size_t ctlbuf[128];
        struct iovec io;
        struct msghdr msgh;
        struct cmsghdr *cmsg;

        char addrbuf[INET6_ADDRSTRLEN];
        for (ifp = ifap; ifp; ifp = ifp->ifa_next) {
            if ((ifp->ifa_flags & (IFF_MULTICAST | IFF_BROADCAST)) == 0)
                continue;

            memset(&address, 0, sizeof(address));
            memset(&msgh, 0, sizeof(msgh));
            msgh.msg_name = &address;
            msgh.msg_iov = &io;
            msgh.msg_iovlen = 1;
            msgh.msg_control = ctlbuf;
            msgh.msg_controllen = sizeof(ctlbuf);

            io.iov_base = &buf;
            io.iov_len = xdr_getpos(&xdr);

            memset(ctlbuf, 0, sizeof(ctlbuf));
            cmsg = CMSG_FIRSTHDR(&msgh);

            if (ifp->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* inaddr = (struct sockaddr_in*)&address;
                struct sockaddr_in* srcaddr = (struct sockaddr_in*)ifp->ifa_addr;
                struct sockaddr_in* broadaddr = (struct sockaddr_in*)ifp->ifa_broadaddr;
                struct in_pktinfo* pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);

                msgh.msg_namelen = sizeof(*inaddr);

                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                msgh.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

                inaddr->sin_family = AF_INET;
                inaddr->sin_port = htons(PMAPPORT);
                memcpy(&inaddr->sin_addr, &broadaddr->sin_addr, sizeof(inaddr->sin_addr));

                memcpy(&pktinfo->ipi_spec_dst.s_addr, &srcaddr->sin_addr, sizeof(srcaddr->sin_addr));

                if (inet_ntop(AF_INET, &inaddr->sin_addr, addrbuf, INET6_ADDRSTRLEN) != NULL)
                    fprintf(stderr, "DST Addr: %s\n", addrbuf);

                sendmsg(udp_socket, &msgh, 0);
            }
            if (ifp->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6* in6addr = (struct sockaddr_in6*)&address;
                struct sockaddr_in6* src6addr = (struct sockaddr_in6*)ifp->ifa_addr;
                struct in6_pktinfo* pktinfo = (struct in6_pktinfo*) CMSG_DATA(cmsg);

                msgh.msg_namelen = sizeof(*in6addr);

                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                msgh.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

                in6addr->sin6_family = AF_INET6;
                in6addr->sin6_port = htons(PMAPPORT);
                inet_pton(AF_INET6, "FF02::202", &in6addr->sin6_addr);

                if (src6addr->sin6_scope_id)
                    pktinfo->ipi6_ifindex = src6addr->sin6_scope_id;

                memcpy(&pktinfo->ipi6_addr, &src6addr->sin6_addr, sizeof(src6addr->sin6_addr));

                if (inet_ntop(AF_INET6, &src6addr->sin6_addr, addrbuf, INET6_ADDRSTRLEN) != NULL)
                    fprintf(stderr, "SRC Addr: %d %s\n", src6addr->sin6_scope_id, addrbuf);

                sendmsg(udp_socket6, &msgh, 0);
            }
        }
        freeifaddrs(ifap);

        struct timeval timeout = { 2, 0 };
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(udp_socket, &fds);
        FD_SET(udp_socket6, &fds);
        short port;

        while (1) {
            if (select(udp_socket6+1, &fds, 0, 0, &timeout) == 0)
                break;

            if (!FD_ISSET(udp_socket, &fds))
                continue;

            memset(&msgh, 0, sizeof(msgh));
            msgh.msg_name = &address;
            msgh.msg_namelen = sizeof(address);
            msgh.msg_iov = &io;
            msgh.msg_iovlen = 1;
            msgh.msg_control = ctlbuf;
            msgh.msg_controllen = sizeof(ctlbuf);

            io.iov_base = &buf;
            io.iov_len = sizeof(buf);

            int len = recvmsg(udp_socket, &msgh, 0);

            port = parse_getport_response(buf, len);

            if (address.ss_family == AF_INET) {

                /* Receive auxiliary data in msgh */
                for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
                        cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
                    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                        struct in_pktinfo* pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
                        if (inet_ntop(AF_INET, &pktinfo->ipi_spec_dst.s_addr, addrbuf, INET6_ADDRSTRLEN) == 0)
                            addrbuf[0] = '\0';
                        fprintf(stderr, "Got IP_PKTINFO on %s\n", addrbuf);
                        break;
                    }
                }

                struct sockaddr_in* inaddr = (struct sockaddr_in*)(&address);
                if (inet_ntop(AF_INET, &inaddr->sin_addr, addrbuf, INET6_ADDRSTRLEN) == 0)
                    addrbuf[0] = '\0';
            }
            if (address.ss_family == AF_INET6) {
                struct sockaddr_in6* in6addr = (struct sockaddr_in6*)(&address);
                if (inet_ntop(AF_INET6, &in6addr->sin6_addr, addrbuf, INET6_ADDRSTRLEN) == 0)
                    addrbuf[0] = '\0';

                for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
                        cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
                    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
                        fprintf(stderr, "Got IPV6_PKTINFO\n");
                        break;
                    }
                }
            }

            fprintf(stderr, "'%s' has VXI-11 on port %d\n", addrbuf, port);
        }

        if (!port)
            fprintf(stderr, "No answer received\n");

        exit(0);
    }

    fprintf(stderr, "%1$s <dotted-address>\n%1$s -b\n", argv[0]);
    exit(EXIT_FAILURE);
}
// vim: set ai expandtab shiftwidth=4 tabstop=4
