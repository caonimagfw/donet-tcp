#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#if defined(__linux__)
  #include <linux/netfilter_ipv4.h>
#elif defined(__APPLE__) && defined(__MACH__)
  #include <sys/ioctl.h>
  #include <net/if.h>
  #include "include/pfvar.h"
  #define SO_ORIGINAL_DST 80
  #define SOL_IP 0
#endif

struct addr_type {
  long ip;
  int port;
};

struct addr_type get_original_addr(int );
struct addr_type get_peer_name(int );

struct addr_type get_original_addr(int fd) {
  struct addr_type return_val;
  return_val.port = -1;

  struct sockaddr_in original_addr;
  int struct_size = sizeof(struct sockaddr_in);

  if(getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &original_addr, &struct_size) != 0) {
    perror("getsockopt");
    return return_val;
  } 
  if(original_addr.sin_family != AF_INET) {
    dprintf(STDERR_FILENO, "getsockopt returns unknown family!");
    return return_val;
  }

  return_val.ip = original_addr.sin_addr.s_addr;
  return_val.port = ntohs(original_addr.sin_port);
  return return_val;
}


struct addr_type get_peer_name(int fd) {
  struct sockaddr_in addr;
  struct addr_type return_val;
  return_val.port = -1;

  int struct_size = sizeof(struct sockaddr_in);
  if(getpeername(fd, &addr, &struct_size) < 0) { 
    perror("getpeername");
    return return_val;
  }

  return_val.ip = addr.sin_addr.s_addr;
  return_val.port = ntohs(addr.sin_port);
  return return_val;
}
