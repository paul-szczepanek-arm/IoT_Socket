/*
 * Copyright (c) 2018-2022 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * $Date:        27. January 2020
 * $Revision:    V1.2.0
 *
 * Project:      IoT Socket API definitions
 *
 * Version 1.2.0
 *   Extended iotSocketRecv/RecvFrom/Send/SendTo (support for polling)
 * Version 1.1.0
 *   Added function iotSocketRecvFrom
 *   Added function iotSocketSendTo
 *   Added function iotSocketGetSockName
 *   Added function iotSocketGetPeerName
 *   Added function iotSocketGetOpt
 *   Removed function iotSocketGetStatus
 *   Changed IP address pointer type to uint8_t *
 *   Added socket option SO_KEEPALIVE and SO_TYPE
 *   Removed socket option SO_REUSEADDR
 * Version 1.0.0
 *   Initial Release
 */

#ifndef IOT_SOCKET_H
#define IOT_SOCKET_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include <stdint.h>

/**** Address Family definitions ****/
#define IOT_SOCKET_AF_INET_UNSPECIFIED  0       ///< Unspecified IP type
#define IOT_SOCKET_AF_INET              1       ///< IPv4
#define IOT_SOCKET_AF_INET6             2       ///< IPv6

/**** Socket Type definitions ****/
#define IOT_SOCKET_SOCK_UNSPECIFIED     0       ///< Unspecified socket
#define IOT_SOCKET_SOCK_STREAM          1       ///< Stream socket
#define IOT_SOCKET_SOCK_DGRAM           2       ///< Datagram socket

/**** Socket Protocol definitions ****/
#define IOT_SOCKET_IPPROTO_UNSPECIFIED  0       ///< Unspecified protocol
#define IOT_SOCKET_IPPROTO_TCP          1       ///< TCP
#define IOT_SOCKET_IPPROTO_UDP          2       ///< UDP

/**** Socket Option Levels ****/
#define IOT_SOCKET_LEVEL_SOL_SOCKET     1       ///< Socket level
#define IOT_SOCKET_LEVEL_IPPROTO_IP     2       ///< IPv4 level
#define IOT_SOCKET_LEVEL_IPPROTO_TCP    3       ///< TCP level
#define IOT_SOCKET_LEVEL_IPPROTO_IPV6   4       ///< IPv6 level

/**** Socket Option definitions ****/
#define IOT_SOCKET_IO_FIONBIO           1  ///< Non-blocking I/O (Set only, default = 0); opt_val = &nbio, opt_len = sizeof(nbio), nbio (integer): 0=blocking, non-blocking otherwise
#define IOT_SOCKET_SO_RCVTIMEO          2  ///< Receive timeout in ms (default = 0); opt_val = &timeout, opt_len = sizeof(timeout)
#define IOT_SOCKET_SO_SNDTIMEO          3  ///< Send timeout in ms (default = 0); opt_val = &timeout, opt_len = sizeof(timeout)
#define IOT_SOCKET_SO_KEEPALIVE         4  ///< Keep-alive messages (default = 0); opt_val = &keepalive, opt_len = sizeof(keepalive), keepalive (integer): 0=disabled, enabled otherwise
#define IOT_SOCKET_SO_TYPE              5  ///< Socket Type (Get only); opt_val = &socket_type, opt_len = sizeof(socket_type), socket_type (integer): IOT_SOCKET_SOCK_xxx

#define IOT_SOCKET_SO_REUSEADDR         6  ///< allow local address reuse
#define IOT_SOCKET_SO_BINDTODEVICE      7  ///< bind socket network interface name
#define IOT_SOCKET_SO_LINGER            8  ///< linger on close if data present
#define IOT_SOCKET_SO_BROADCAST         9  ///< permit to send and to receive broadcast messages
#define IOT_SOCKET_IP_MULTICAST_IF      10 ///< set the device for outgoing multicast packets on the socket
#define IOT_SOCKET_IP_MULTICAST_TTL     11 ///< set or read the time-to-live value of outgoing multicast packets for this socket
#define IOT_SOCKET_IP_MULTICAST_LOOP    12 ///< control whether the socket sees multicast packets that it has send itself
#define IOT_SOCKET_IP_PKTINFO           13 ///< pass an IP_PKTINFO ancillary message that contains a pktinfo structure that supplies some information about the incoming packet
#define IOT_SOCKET_IP_ADD_MEMBERSHIP    14 ///< join to a multicast group
#define IOT_SOCKET_IP_DROP_MEMBERSHIP   15 ///< leave a multicast group
#define IOT_SOCKET_IPV6_V6ONLY          16 ///< restricted to sending and receiving IPv6 packets only
#define IOT_SOCKET_IPV6_PKTINFO         17 ///< set delivery of the IPV6_PKTINFO control message on incoming datagrams. Such control messages contain a struct in6_pktinfo
#define IOT_SOCKET_IPV6_MULTICAST_IF    18 ///< set the device for outgoing multicast packets on the socket
#define IOT_SOCKET_IPV6_MULTICAST_HOPS  19 ///< set the multicast hop limit for the socket
#define IOT_SOCKET_IPV6_MULTICAST_LOOP  20 ///< control whether the socket sees multicast packets that it has sent itself
#define IOT_SOCKET_IPV6_ADD_MEMBERSHIP  21 ///< join a multicast group
#define IOT_SOCKET_IPV6_DROP_MEMBERSHIP 22 ///< leave a multicast group
#define IOT_SOCKET_TCP_NODELAY          23 ///< don't delay sending to coalesce packets
#define IOT_SOCKET_TCP_KEEPIDLE         24 ///< keep alive interval, use seconds for get/setsockopt
#define IOT_SOCKET_TCP_KEEPINTVL        25 ///< Use seconds for get/setsockopt
#define IOT_SOCKET_TCP_KEEPCNT          26 ///< Use number of probes sent for get/setsockopt

/**** Socket Return Codes ****/
#define IOT_SOCKET_ERROR                (-1)    ///< Unspecified error
#define IOT_SOCKET_ESOCK                (-2)    ///< Invalid socket
#define IOT_SOCKET_EINVAL               (-3)    ///< Invalid argument
#define IOT_SOCKET_ENOTSUP              (-4)    ///< Operation not supported
#define IOT_SOCKET_ENOMEM               (-5)    ///< Not enough memory
#define IOT_SOCKET_EAGAIN               (-6)    ///< Operation would block or timed out
#define IOT_SOCKET_EINPROGRESS          (-7)    ///< Operation in progress
#define IOT_SOCKET_ETIMEDOUT            (-8)    ///< Operation timed out
#define IOT_SOCKET_EISCONN              (-9)    ///< Socket is connected
#define IOT_SOCKET_ENOTCONN             (-10)   ///< Socket is not connected
#define IOT_SOCKET_ECONNREFUSED         (-11)   ///< Connection rejected by the peer
#define IOT_SOCKET_ECONNRESET           (-12)   ///< Connection reset by the peer
#define IOT_SOCKET_ECONNABORTED         (-13)   ///< Connection aborted locally
#define IOT_SOCKET_EALREADY             (-14)   ///< Connection already in progress
#define IOT_SOCKET_EADDRINUSE           (-15)   ///< Address in use
#define IOT_SOCKET_EHOSTNOTFOUND        (-16)   ///< Host not found

/**** Send/recv message flags used as parameter for iotSocketSendMsg and iotSocketRecvMsg ****/
#define IOT_SOCKET_MSG_PEEK      0x1 ///< Peeks at an incoming message
#define IOT_SOCKET_MSG_DONTWAIT  0x2 ///< Nonblocking i/o for this operation only
#define IOT_SOCKET_MSG_MORE      0x4 ///< Sender will send more

/**** Message flags stored in msg_flags in the iot_msghdr struct ****/
#define IOT_SOCKET_MSG_TRUNC     0x1 ///< Some data was discarded because it was larger than the buffer available
#define IOT_SOCKET_MSG_CTRUNC    0x2 ///< Some control data was discarded because the buffer for ancillary data was too small

/**** Socket shutdown option ****/
#define IOT_SOCKET_SHUTDOWN_RD   0x1 ///< stop receiving on socket
#define IOT_SOCKET_SHUTDOWN_WR   0x2 ///< stop sending on socket
#define IOT_SOCKET_SHUTDOWN_RDWR 0x3 ///< stop receiving and sending on socket

#define ALIGN_4(size) (((size) + 3) & ~3)

/* macros to access aAncillary data stored in iot_msghdr->msg_control */

/** Return pointer to CMSG payload */
#define IOT_CMSG_DATA(cmsg) ((void *) ((uint8_t *) (cmsg) + sizeof(iot_cmsghdr)))

/** Return length of header + payload */
#define IOT_CMSG_LEN(length) (sizeof(iot_cmsghdr) + length)

/** Return length of header + payload + padding */
#define IOT_CMSG_SPACE(length) (sizeof(iot_cmsghdr) + ALIGN_4(length))

/** Return first cmsg */
#define IOT_CMSG_FIRSTHDR(mhdr) \
  (iot_cmsghdr *) ((sizeof(iot_cmsghdr) > (mhdr)->msg_controllen) ? NULL : ((mhdr)->msg_control))

/** Return next cmsg header in array after given cmsg, if cmsg is null, return the first header */
#define IOT_CMSG_NXTHDR(mhdr, cmsg)                                                \
  (                                                                                \
    ((cmsg) == NULL) ? IOT_CMSG_FIRSTHDR(mhdr)                                     \
    : (iot_cmsghdr *) (((((uint8_t *)(cmsg)) + IOT_CMSG_SPACE((cmsg)->cmsg_len)) > \
        (((uint8_t *)((mhdr)->msg_control)) + (mhdr)->msg_controllen)) ? NULL      \
       : ((uint8_t *) (cmsg) + ALIGN_4((cmsg)->cmsg_len)))                         \
  )

/* types for addresses iotSocketRecvMsg and iotSocketSendMsg */

typedef struct iot_iovec {
  void    *iov_base;
  uint32_t iov_len;
} iot_iovec ;

typedef struct iot_cmsghdr {
  uint32_t cmsg_len;   ///< number of bytes, including header
  int32_t  cmsg_level; ///< originating protocol
  int32_t  cmsg_type;  ///< protocol-specific type
} iot_cmsghdr;

typedef struct iot_msghdr {
  void      *msg_name;       ///< ptr to socket address structure
  uint32_t   msg_namelen;    ///< size of socket address structure
  iot_iovec *msg_iov;        ///< scatter/gather array
  int32_t    msg_iovlen;     ///< number of elements in msg_iov
  void      *msg_control;    ///< ancillary data
  uint32_t   msg_controllen; ///< ancillary data buffer length
  int32_t    msg_flags;      ///< flags on received message
} iot_msghdr;

/* types for addresses */

typedef struct iot_in_addr {
  uint32_t s_addr;
} iot_in_addr;

typedef struct iot_in6_addr {
  union {
    uint32_t s6_addr32[4];
    uint8_t  s6_addr[16];
  };
} iot_in6_addr;

typedef struct iot_sockaddr_in {
  uint8_t     sin_len;    ///<  length of this structure
  uint8_t     sin_family; ///<  IOT_SOCKET_AF_INET
  uint16_t    sin_port;   ///< Transport layer port number
  iot_in_addr sin_addr;   ///< IPv4 address
} iot_sockaddr_in;

typedef struct iot_sockaddr_in6 {
  uint8_t      sin6_len;      ///<  length of this structure
  uint8_t      sin6_family;   ///<  IOT_SOCKET_AF_INET6
  uint16_t     sin6_port;     ///<  Transport layer port number
  uint32_t     sin6_flowinfo; ///<  IPv6 flow information
  iot_in6_addr sin6_addr;     ///<  IPv6 address
  uint32_t     sin6_scope_id; ///<  Set of interfaces for scope
} iot_sockaddr_in6;

typedef struct iot_sockaddr_in_any {
  union {
    struct {
      uint8_t  sa_len;    ///<  length of this structure
      uint8_t  sa_family; ///<  IOT_SOCKET_AF_INET or IOT_SOCKET_AF_INET6
      uint16_t sa_port;   ///<  Transport layer port number
    };
    iot_sockaddr_in  in;
    iot_sockaddr_in6 in6;
  };
} iot_sockaddr_in_any;

typedef struct iot_in_pktinfo {
  uint32_t    ipi_ifindex;  ///<  Interface index
  iot_in_addr ipi_addr;     ///<  Destination (from header) address
} iot_in_pktinfo;

typedef struct iot_in6_pktinfo {
  uint32_t     ipi6_ifindex;  ///<  Interface index
  iot_in6_addr ipi6_addr;     ///<  Destination (from header) address
} iot_in6_pktinfo;

/* types for socket options */

/** Used as parameter for IOT_SOCKET_IP_ADD_MEMBERSHIP and IOT_SOCKET_IP_DROP_MEMBERSHIP */
typedef struct iot_ip_mreq {
    iot_in_addr imr_multiaddr; ///< IP multicast address of group
    iot_in_addr imr_interface; ///< local IP address of interface
} iot_ip_mreq;

/** Used as parameter for IOT_SOCKET_IPV6_ADD_MEMBERSHIP and IOT_SOCKET_IPV6_DROP_MEMBERSHIP */
typedef struct iot_ipv6_mreq {
  iot_in6_addr ipv6mr_multiaddr; ///<  IPv6 multicast addr
  uint32_t     ipv6mr_interface; ///<  interface index, or 0
} iot_ipv6_mreq;

/** Used as parameter for IOT_SOCKET_SO_LINGER */
typedef struct iot_opt_linger {
  int32_t l_onoff;  ///< option on/off
  int32_t l_linger; ///< linger time in seconds
} iot_opt_linger;

/**
  \brief         Create a communication socket.
  \param[in]     af       address family.
  \param[in]     type     socket type.
  \param[in]     protocol socket protocol.
  \return        status information:
                 - Socket identification number (>=0).
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument.
                 - \ref IOT_SOCKET_ENOTSUP       = Operation not supported.
                 - \ref IOT_SOCKET_ENOMEM        = Not enough memory.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketCreate (int32_t af, int32_t type, int32_t protocol);

/**
  \brief         Assign a local address to a socket.
  \param[in]     socket   socket identification number.
  \param[in]     ip       pointer to local IP address.
  \param[in]     ip_len   length of 'ip' address in bytes.
  \param[in]     port     local port number.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (address or socket already bound).
                 - \ref IOT_SOCKET_EADDRINUSE    = Address already in use.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketBind (int32_t socket, const uint8_t *ip, uint32_t ip_len, uint16_t port);

/**
  \brief         Listen for socket connections.
  \param[in]     socket   socket identification number.
  \param[in]     backlog  number of connection requests that can be queued.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (socket not bound).
                 - \ref IOT_SOCKET_ENOTSUP       = Operation not supported.
                 - \ref IOT_SOCKET_EISCONN       = Socket is already connected.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketListen (int32_t socket, int32_t backlog);

/**
  \brief         Accept a new connection on a socket.
  \param[in]     socket   socket identification number.
  \param[out]    ip       pointer to buffer where address of connecting socket shall be returned (NULL for none).
  \param[in,out] ip_len   pointer to length of 'ip' (or NULL if 'ip' is NULL):
                 - length of supplied 'ip' on input.
                 - length of stored 'ip' on output.
  \param[out]    port     pointer to buffer where port of connecting socket shall be returned (NULL for none).
  \return        status information:
                 - socket identification number of accepted socket (>=0).
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (socket not in listen mode).
                 - \ref IOT_SOCKET_ENOTSUP       = Operation not supported (socket type does not support accepting connections).
                 - \ref IOT_SOCKET_ECONNRESET    = Connection reset by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block or timed out (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketAccept (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port);

/**
  \brief         Connect a socket to a remote host.
  \param[in]     socket   socket identification number.
  \param[in]     ip       pointer to remote IP address.
  \param[in]     ip_len   length of 'ip' address in bytes.
  \param[in]     port     remote port number.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument.
                 - \ref IOT_SOCKET_EALREADY      = Connection already in progress.
                 - \ref IOT_SOCKET_EINPROGRESS   = Operation in progress.
                 - \ref IOT_SOCKET_EISCONN       = Socket is connected.
                 - \ref IOT_SOCKET_ECONNREFUSED  = Connection rejected by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EADDRINUSE    = Address already in use.
                 - \ref IOT_SOCKET_ETIMEDOUT     = Operation timed out.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketConnect (int32_t socket, const uint8_t *ip, uint32_t ip_len, uint16_t port);

/**
  \brief         Receive data or check if data is available on a connected socket.
  \param[in]     socket   socket identification number.
  \param[out]    buf      pointer to buffer where data should be stored.
  \param[in]     len      length of buffer (in bytes), set len = 0 to check if data is available.
  \return        status information:
                 - number of bytes received (>=0), if len != 0.
                 - 0                             = Data is available (len = 0).
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to buffer or length).
                 - \ref IOT_SOCKET_ENOTCONN      = Socket is not connected.
                 - \ref IOT_SOCKET_ECONNRESET    = Connection reset by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block or timed out (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketRecv (int32_t socket, void *buf, uint32_t len);

/**
  \brief         Receive data or check if data is available on a socket.
  \param[in]     socket   socket identification number.
  \param[out]    buf      pointer to buffer where data should be stored.
  \param[in]     len      length of buffer (in bytes), set len = 0 to check if data is available.
  \param[out]    ip       pointer to buffer where remote source address shall be returned (NULL for none).
  \param[in,out] ip_len   pointer to length of 'ip' (or NULL if 'ip' is NULL):
                 - length of supplied 'ip' on input.
                 - length of stored 'ip' on output.
  \param[out]    port     pointer to buffer where remote source port shall be returned (NULL for none).
  \return        status information:
                 - number of bytes received (>=0), if len != 0.
                 - 0                             = Data is available (len = 0).
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to buffer or length).
                 - \ref IOT_SOCKET_ENOTCONN      = Socket is not connected.
                 - \ref IOT_SOCKET_ECONNRESET    = Connection reset by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block or timed out (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketRecvFrom (int32_t socket, void *buf, uint32_t len, uint8_t *ip, uint32_t *ip_len, uint16_t *port);

/**
  \brief         Send data or check if data can be sent on a connected socket.
  \param[in]     socket   socket identification number.
  \param[in]     buf      pointer to buffer containing data to send.
  \param[in]     len      length of data (in bytes), set len = 0 to check if data can be sent.
  \return        status information:
                 - number of bytes sent (>=0), if len != 0.
                 - 0                             = Data can be sent (len = 0).
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to buffer or length).
                 - \ref IOT_SOCKET_ENOTCONN      = Socket is not connected.
                 - \ref IOT_SOCKET_ECONNRESET    = Connection reset by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block or timed out (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketSend (int32_t socket, const void *buf, uint32_t len);

/**
  \brief         Send data or check if data can be sent on a socket.
  \param[in]     socket   socket identification number.
  \param[in]     buf      pointer to buffer containing data to send.
  \param[in]     len      length of data (in bytes), set len = 0 to check if data can be sent.
  \param[in]     ip       pointer to remote destination IP address.
  \param[in]     ip_len   length of 'ip' address in bytes.
  \param[in]     port     remote destination port number.
  \return        status information:
                 - number of bytes sent (>=0), if len != 0.
                 - 0                             = Data can be sent (len = 0).
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to buffer or length).
                 - \ref IOT_SOCKET_ENOTCONN      = Socket is not connected.
                 - \ref IOT_SOCKET_ECONNRESET    = Connection reset by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block or timed out (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketSendTo (int32_t socket, const void *buf, uint32_t len, const uint8_t *ip, uint32_t ip_len, uint16_t port);

/**
  \brief         Send data using a message struct.
  \param[in]     socket   socket identification number.
  \param[in]     message  message struct containing both the destination address and the buffers for the outgoing message.
                          The msg_flags member of the message struct is ignored.
  \param[in]     flags    flags for the operation:
                 - \ref IOT_SOCKET_MSG_DONTWAIT  = Nonblocking I/O for this operation only
                 - \ref IOT_SOCKET_MSG_MORE      = Sender will send more
  \return        status information:
                 - number of bytes sent (>=0)
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to message).
                 - \ref IOT_SOCKET_ENOTCONN      = Socket is not connected.
                 - \ref IOT_SOCKET_ECONNRESET    = Connection reset by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block or timed out (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketSendMsg (int32_t socket, const iot_msghdr *message, int32_t flags);

/**
  \brief         Receive data using a message struct.
  \param[in]     socket   socket identification number.
  \param[out]    message  message struct containing both the buffer to store the source address and the buffers for the incoming message.
                          Size of buffer pointed to by msg_name and the value of msg_namelen must be at least sizeof(iot_sockaddr_in_any).
                          The msg_flags member of the message struct is ignored on input but may contain meaningful values on output.
  \param[in]     flags    flags for the operation:
                 - \ref IOT_SOCKET_MSG_PEEK      = Peeks at an incoming message
                 - \ref IOT_SOCKET_MSG_DONTWAIT  = Nonblocking I/O for this operation only
  \return        status information:
                 - number of bytes received (>=0)
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to message).
                 - \ref IOT_SOCKET_ENOTCONN      = Socket is not connected.
                 - \ref IOT_SOCKET_ECONNRESET    = Connection reset by the peer.
                 - \ref IOT_SOCKET_ECONNABORTED  = Connection aborted locally.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block or timed out (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketRecvMsg (int32_t socket, iot_msghdr *message, int32_t flags);


/**
  \brief         Retrieve local IP address and port of a socket.
  \param[in]     socket   socket identification number.
  \param[out]    ip       pointer to buffer where local address shall be returned (NULL for none).
  \param[in,out] ip_len   pointer to length of 'ip' (or NULL if 'ip' is NULL):
                 - length of supplied 'ip' on input.
                 - length of stored 'ip' on output.
  \param[out]    port     pointer to buffer where local port shall be returned (NULL for none).
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to buffer or length).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketGetSockName (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port);

/**
  \brief         Retrieve remote IP address and port of a socket.
  \param[in]     socket   socket identification number.
  \param[out]    ip       pointer to buffer where remote address shall be returned (NULL for none).
  \param[in,out] ip_len   pointer to length of 'ip' (or NULL if 'ip' is NULL):
                 - length of supplied 'ip' on input.
                 - length of stored 'ip' on output.
  \param[out]    port     pointer to buffer where remote port shall be returned (NULL for none).
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument (pointer to buffer or length).
                 - \ref IOT_SOCKET_ENOTCONN      = Socket is not connected.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketGetPeerName (int32_t socket, uint8_t *ip, uint32_t *ip_len, uint16_t *port);

/**
  \brief         Get socket option.
  \param[in]     socket   socket identification number.
  \param[in]     opt_id   option identifier.
  \param[out]    opt_val  pointer to the buffer that will receive the option value.
  \param[in,out] opt_len  pointer to length of the option value:
                 - length of buffer on input.
                 - length of data on output.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument.
                 - \ref IOT_SOCKET_ENOTSUP       = Operation not supported.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketGetOpt (int32_t socket, int32_t opt_id, void *opt_val, uint32_t *opt_len);

/**
  \brief         Set socket option.
  \param[in]     socket   socket identification number.
  \param[in]     opt_id   option identifier.
  \param[in]     opt_val  pointer to the option value.
  \param[in]     opt_len  length of the option value in bytes.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument.
                 - \ref IOT_SOCKET_ENOTSUP       = Operation not supported.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketSetOpt (int32_t socket, int32_t opt_id, const void *opt_val, uint32_t opt_len);

/**
  \brief         Close and release a socket.
  \param[in]     socket   socket identification number.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EAGAIN        = Operation would block (may be called again).
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketClose (int32_t socket);

/**
  \brief         Stop sending or receiving on a socket.
  \param[in]     socket   socket identification number.
  \param[in]     option   option for the operation:
                 - \ref IOT_SOCKET_SHUTDOWN_RD   = stop receiving
                 - \ref IOT_SOCKET_SHUTDOWN_WR   = stop sending
                 - \ref IOT_SOCKET_SHUTDOWN_RDWR = stop receiving and sending
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ESOCK         = Invalid socket.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketShutdown (int32_t socket, int32_t option);

/**
  \brief         Set socket id in the mask.
  \note          Mask can be used with iotSocketSelect. User guarantees that size of mask is at least iotSocketMaskGetSize() bytes.
  \param[in]     socket Socket id.
  \param[in,out] mask   pointer to a mask of sockets.
 */
extern void iotSocketMaskSet (int32_t socket, void *mask);

/**
  \brief         Unset socket id in the mask.
  \note          Mask can be used with iotSocketSelect. User guarantees that size of mask is at least iotSocketMaskGetSize() bytes.
  \param[in]     socket Socket id.
  \param[in,out] mask   pointer to a mask of sockets.
 */
extern void iotSocketMaskUnset (int32_t socket, void *mask);

/**
  \brief     Return if socket id is set in the mask.
  \note      Mask can be used with iotSocketSelect. User guarantees that size of mask is at least iotSocketMaskGetSize() bytes.
  \param[in] socket Socket id.
  \param[in] mask   pointer to a mask of sockets.
  \return    - 0 = Socket id is not set in mask.
             - 1 = Socket id is set in mask.
 */
extern uint32_t iotSocketMaskIsSet (int32_t socket, const void *mask);

/**
  \brief         Zero the mask of sockets.
  \note          Mask can be used with iotSocketSelect. User guarantees that size of mask is at least iotSocketMaskGetSize() bytes.
  \param[in,out] mask pointer to a mask of sockets.
 */
extern void iotSocketMaskZero (void *mask);

/**
  \brief  Get size in bytes of the socket mask. Mask can be used with iotSocketSelect.
  \return - greater than 0 = Size in bytes of the mask.
          - 0              = iotSocketSelect operation not supported.
 */
extern uint32_t iotSocketMaskGetSize ();

/**
  \brief         Block until a socket in one of the masks is signalled or timeout happens.
  \param[in,out] read_mask pointer to a mask of sockets to wait for reading, returns sockets with pending data.
  \param[in,out] write_mask pointer to a mask of sockets to wait for writing, returns sockets that where written to.
  \param[in,out] exception_mask pointer to a mask of sockets to wait for exceptions, returns sockets with exceptions.
  \param[in]     timeout_ms how long to wait before returning if no signals received.
  \return        status information:
                 - number of sockets signalled (>=0)
                 - \ref IOT_SOCKET_ENOTSUP       = iotSocketSelect operation not supported.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketSelect (void *read_mask, void *write_mask, void *exception_mask, uint32_t timeout_ms);

/**
  \brief         Retrieve host IP address from host name.
  \param[in]     name     host name.
  \param[in]     af       address family.
  \param[out]    ip       pointer to buffer where resolved IP address shall be returned.
  \param[in,out] ip_len   pointer to length of 'ip':
                 - length of supplied 'ip' on input.
                 - length of stored 'ip' on output.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_EINVAL        = Invalid argument.
                 - \ref IOT_SOCKET_ENOTSUP       = Operation not supported.
                 - \ref IOT_SOCKET_ETIMEDOUT     = Operation timed out.
                 - \ref IOT_SOCKET_EHOSTNOTFOUND = Host not found.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotSocketGetHostByName (const char *name, int32_t af, uint8_t *ip, uint32_t *ip_len);

/**
  \brief         Convert iot_in_addr into string.
  \param[in]     address  address to convert.
  \param[out]    buf      pointer to buffer for the string.
  \param[in]     buf_size size of the buffer.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotIpAddrToString (const iot_in_addr *address, char *buf, uint32_t buf_size);

/**
  \brief         Convert iot_in6_addr into string.
  \param[in]     address  address to convert.
  \param[out]    buf      pointer to buffer for the string.
  \param[in]     buf_size size of the buffer.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotIp6AddrToString (const iot_in6_addr *address, char *buf, uint32_t buf_size) ;

/**
  \brief         Convert string into an iot_in_addr address.
  \param[in]     address_string  address to convert in a null terminated string.
  \param[out]    buf             pointer to address struct.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotStringToIpAddr (const char *address_string, iot_in_addr *address);

/**
  \brief         Convert string into an iot_in6_addr address.
  \param[in]     address_string  address to convert in a null terminated string.
  \param[out]    buf             pointer to address struct.
  \return        status information:
                 - 0                             = Operation successful.
                 - \ref IOT_SOCKET_ERROR         = Unspecified error.
 */
extern int32_t iotStringToIp6Addr (const char *address_string, iot_in6_addr *address);

#ifdef  __cplusplus
}
#endif

#endif /* IOT_SOCKET_H */
