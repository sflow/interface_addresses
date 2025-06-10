/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#define _GNU_SOURCE

#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sched.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h> // for isspace() etc.
#include <sched.h> // for setns()
#include <linux/in6.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <netdb.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>

// limit the number of chars we will read from each line
// (there can be more than this - my_readline will chop for us)
#define MAX_PROC_LINE_CHARS 320
#define HSP_VNIC_MAX_FNAME_LEN 255
#define HSP_VNIC_MAX_LINELEN 512
#define PROCFS_STR "/proc"

/*________________---------------------------__________________
  ________________          utils            __________________
  ----------------___________________________------------------
*/

char *trimWhitespace(char *str, uint32_t len)
{
  // NULL -> NULL
  if(str == NULL)
    return NULL;
    
  // "" -> NULL
  if(len == 0
     || *str == '\0')
    return NULL;
    
  char *end = str + len - 1;

  // Trim leading space
  while(isspace(*str)) {
    // also return NULL for a string with only spaces in it
    // (don't want that condition to slip through unnoticed)
    if(++str > end)
      return NULL;
  }

  // Trim trailing space
  while(end > str
	&& isspace(*end))
    end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}

static int isSeparator(char ch, char *separators) {
  if(separators == NULL) return false;
  for(char *sep = separators; (*sep) != '\0'; sep++)
    if((*sep) == ch) return true;
  return false;
}

char *parseNextTok(char **str, char *sep, int delim, char quot, int trim, char *buf, int buflen)
{
  if(str == NULL) return NULL;
  
  char *a = (*str);
  
  if(a == NULL) {
    // We hit EOS last time and indicated it by setting *str to NULL.
    // Last time we may have returned an empty string to indicate a
    // trailing delimiter (or the whole input was ""). This time
    // we terminate for sure.
    return NULL;
  }

  // initialize buffer to empty string
  buf[0] = '\0';

  if(a[0] == '\0') {
    // return the empty string and make sure we terminate next time
    *str = NULL;
    return buf;
  }

  int buflast = buflen-1;
  int len = 0;

  if(delim && isSeparator(a[0], sep)) {
    // leading delimiter, so don't advance - just allow an
    // empty-string token to be generated.  The delimiter
    // will be consumed below
  }
  else {
    if(!delim) {
      // skip separators
      while(a[0] != '\0' && isSeparator(a[0], sep)) a++;
    }
    if(a[0] == quot) {
      a++; // consume leading quote
      while(a[0] != '\0') {
	if(a[0] == quot) {
	  a++; // consume it
	  if(a[0] != quot) break; // quotquot -> quot
	}
	if(len < buflast) buf[len++] = a[0];
	a++;
      }
    }
    else {
      while(a[0] != '\0' && !isSeparator(a[0], sep)) {
	if(len < buflast) buf[len++] = a[0];
	a++;
      }
    }
  }
  buf[len] = '\0';

  if(!delim) {
    // skip separators again - in case there are no more tokens
    // and this takes us all the way to EOS
    while(a[0] != '\0' && isSeparator(a[0], sep)) a++;
  }

  if(a[0] == '\0') {
    // at EOS, so indicate to the caller that there are no more tokens after this one
    *str = NULL;
  }
  else {
    if(delim) {
      // since we got a token, we need
      // to consume the trailing delimiter if it is there
      if(isSeparator(a[0], sep)) a++;
      // this may mean we are at EOS now, but that implies
      // there is one more (empty-string) token,  so it's
      // correct.
    }
    *str = a;
  }

  return trim ? trimWhitespace(buf, len) : buf;
}

int my_readline(FILE *ff, char *buf, uint32_t len, int *p_truncated) {
  // read up to len-1 chars from line, but consume the whole line.
  // return number of characters read (0 for empty line), or EOF if file
  // was already at EOF. Always null-terminate the buffer. Indicate
  // number of truncated characters with the pointer provided.
  if(buf == NULL
     || len < 2) {
    // must have at least a 2-byte buffer 
    return EOF;
  }
  int chop=0;
  uint32_t count=0;
  bool atEOF=true;
  int ch;
  while((ch = fgetc(ff)) != EOF) {
    atEOF = false;
    // EOL on CR, LF or CRLF
    if(ch == 10 || ch == 13) {
      if(ch == 13) {
	// peek for CRLF
	if((ch = fgetc(ff)) != 10)
	  ungetc(ch, ff);
      }
      break;
    }
    if(count < (len-1)
       && ch >= 0
       && ch <= 255)
      buf[count++] = ch;
    else
      chop++;
  }
  buf[count] = '\0';
  if(p_truncated)
    *p_truncated = chop;
  return atEOF ? EOF : count;
}

/*________________---------------------------__________________
  ________________     hex2bin, bin2hex      __________________
  ----------------___________________________------------------
*/

static u_char hex2bin(u_char c)
{
  return (isdigit(c) ? (c)-'0': ((toupper(c))-'A')+10)  & 0xf;
}

static u_char bin2hex(int nib)
{
  return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib);
}

/*_________________---------------------------__________________
  _________________   printHex, hexToBinary   __________________
  -----------------___________________________------------------
*/

int printHex(const u_char *a, int len, u_char *buf, int bufLen, int prefix)
{
  int b = 0;
  if(prefix) {
    buf[b++] = '0';
    buf[b++] = 'x';
  }
  for(int i = 0; i < len; i++) {
    if(b > (bufLen - 2)) return 0; // must be room for 2 characters
    u_char byte = a[i];
    buf[b++] = bin2hex(byte >> 4);
    buf[b++] = bin2hex(byte & 0x0f);
  }

  // add NUL termination
  buf[b] = '\0';

  return b;
}

int hexToBinary(u_char *hex, u_char *bin, uint32_t binLen)
{
  // read from hex into bin, up to max binLen chars, return number written
  u_char *h = hex;
  u_char *b = bin;
  u_char c;
  uint32_t i = 0;

  while((c = *h++) != '\0') {
    if(isxdigit(c)) {
      u_char val = hex2bin(c);
      if(isxdigit(*h)) {
	c = *h++;
	val = (val << 4) | hex2bin(c);
      }
      *b++ = val;
      if(++i >= binLen) return i;
    }
    else if(c != '.' &&
	    c != '-' &&
	    c != ':') { // allow a variety of byte-separators
      return i;
    }
  }
  return i;
}

/*________________---------------------------__________________
  ________________   netns_identify_pid      __________________
  ----------------___________________________------------------
adapted from iproute2
*/

#define NETNS_RUN_DIR "/var/run/netns"

int netns_identify_pid(const pid_t nspid, char *name, int len)
{
	char net_path[PATH_MAX];
	int netns = -1, ret = -1;
	struct stat netst;
	DIR *dir;
	struct dirent *entry;

	name[0] = '\0';

	snprintf(net_path, sizeof(net_path), "/proc/%u/ns/net", nspid);
	netns = open(net_path, O_RDONLY);
	if (netns < 0) {
		fprintf(stderr, "Cannot open network namespace: %s\n",
			strerror(errno));
		goto out;
	}
	if (fstat(netns, &netst) < 0) {
		fprintf(stderr, "Stat of netns failed: %s\n",
			strerror(errno));
		goto out;
	}
	dir = opendir(NETNS_RUN_DIR);
	if (!dir) {
		/* Succeed treat a missing directory as an empty directory */
		if (errno == ENOENT) {
			ret = 0;
			goto out;
		}

		fprintf(stderr, "Failed to open directory %s:%s\n",
			NETNS_RUN_DIR, strerror(errno));
		goto out;
	}

	while ((entry = readdir(dir))) {
		char name_path[PATH_MAX];
		struct stat st;

		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(name_path, sizeof(name_path), "%s/%s",	NETNS_RUN_DIR,
			entry->d_name);

		if (stat(name_path, &st) != 0)
			continue;

		if ((st.st_dev == netst.st_dev) &&
		    (st.st_ino == netst.st_ino)) {
			strncpy(name, entry->d_name, len);
		}
	}
	ret = 0;
	closedir(dir);
out:
	if (netns >= 0)
		close(netns);
	return ret;

}

/*________________---------------------------__________________
  ________________    readVNICInterfaces     __________________
  ----------------___________________________------------------
*/

#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0) || (__GLIBC__ <= 2 && __GLIBC_MINOR__ < 14))
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000	/* New network namespace (lo, device, names sockets, etc) */
#endif

#define MY_SETNS(fd, nstype) syscall(__NR_setns, fd, nstype)
#else
#define MY_SETNS(fd, nstype) setns(fd, nstype)
#endif
  
int readVNICInterfaces(uint32_t nspid)  {
  fprintf(stderr, "readVNICInterfaces: pid=%u\n", nspid);
  char netns_id[256];
  int rc = netns_identify_pid(nspid, netns_id, 256);
  if(rc == 0)
    fprintf(stderr, "netns_identify_pid() -> %s\n", netns_id);
  else
    fprintf(stderr, "netns_identify_pid() failed : %s\n", strerror(errno));
  
  // open /proc/<nspid>/ns/net
  char topath[HSP_VNIC_MAX_FNAME_LEN+1];
  snprintf(topath, HSP_VNIC_MAX_FNAME_LEN, PROCFS_STR "/%u/ns/net", nspid);
  int nsfd = open(topath, O_RDONLY | O_CLOEXEC);
  if(nsfd < 0) {
    fprintf(stderr, "cannot open %s : %s\n", topath, strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct stat statBuf;
  if(fstat(nsfd, &statBuf) == 0) {
    fprintf(stderr, "vm namespace dev.inode == %lu.%lu\n", statBuf.st_dev, statBuf.st_ino);
  }

  /* set network namespace
     CLONE_NEWNET means nsfd must refer to a network namespace
  */
  if(MY_SETNS(nsfd, CLONE_NEWNET) < 0) {
    fprintf(stderr, "seting network namespace failed: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* From "man 2 unshare":  This flag has the same effect as the clone(2)
     CLONE_NEWNS flag. Unshare the mount namespace, so that the calling
     process has a private copy of its namespace which is not shared with
     any other process. Specifying this flag automatically implies CLONE_FS
     as well. Use of CLONE_NEWNS requires the CAP_SYS_ADMIN capability. */
  if(unshare(CLONE_NEWNS) < 0) {
    fprintf(stderr, "seting network namespace failed: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  int fd = socket(PF_INET, SOCK_DGRAM, 0);
  if(fd < 0) {
    fprintf(stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
  }

  FILE *procV6 = fopen(PROCFS_STR "/net/if_inet6", "r");
  if(procV6) {
    char line[MAX_PROC_LINE_CHARS];
    int lineNo = 0;
    int truncated;
    while(my_readline(procV6, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
      // expect lines of the form "<address> <netlink_no> <prefix_len(HEX)> <scope(HEX)> <flags(HEX)> <deviceName>
      // (with a header line on the first row)
      char devName[MAX_PROC_LINE_CHARS];
      u_char addr[MAX_PROC_LINE_CHARS];
      u_int devNo, maskBits, scope, flags;
      ++lineNo;
      if(sscanf(line, "%s %x %x %x %x %s\n",
		addr,
		&devNo,
		&maskBits,
		&scope,
		&flags,
		devName) == 6) {
	    
	uint32_t devLen = strnlen(devName, MAX_PROC_LINE_CHARS-1);
	char *trimmed = trimWhitespace(devName, devLen);
	if(trimmed) {
	  struct in6_addr ip6 = {};
	  if(hexToBinary(addr, ip6.s6_addr, 16) == 16) {
	    char buf[128];
	    inet_ntop(AF_INET6, &ip6, buf, 128);
	    fprintf(stderr, "dev %s has v6 addr %s\n", devName, buf); 
	  }
	}
      }
    }
    fclose(procV6);
  }
  
  FILE *procFile = fopen(PROCFS_STR "/net/dev", "r");
  if(procFile) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    char line[MAX_PROC_LINE_CHARS];
    int lineNo = 0;
    int truncated;
    while(my_readline(procFile, line, MAX_PROC_LINE_CHARS, &truncated) != EOF) {
      if(lineNo++ < 2)
	continue; // skip headers
      char buf[MAX_PROC_LINE_CHARS];
      char *p = line;
      char *devName = parseNextTok(&p, " \t:", false, '\0', false, buf, MAX_PROC_LINE_CHARS);
      if(!devName) {
	fprintf(stderr, "failed to parse devName from line: %s\n", line);
	continue;
      }
      strncpy(ifr.ifr_name, devName, sizeof(ifr.ifr_name)-1);
      // Get the flags for this interface
      if(ioctl(fd,SIOCGIFFLAGS, &ifr) < 0) {
	fprintf(stderr, "dev %s Get SIOCGIFFLAGS failed : %s\n",
		devName,
		strerror(errno));
	continue;
      }
      int up = (ifr.ifr_flags & IFF_UP) ? true : false;
      int loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? true : false;
      // ifIndex
      if(ioctl(fd,SIOCGIFINDEX, &ifr) < 0) {
	fprintf(stderr, "dev %s Get SIOCGIFINDEX failed : %s\n",
		devName,
		strerror(errno));
      }
      int ifIndex = ifr.ifr_ifindex;
      // see if we can get an IP address
      if(ioctl(fd,SIOCGIFADDR, &ifr) < 0) {
	fprintf(stderr, "dev %s Get SIOCGIFADDR failed : %s\n",
		devName,
		strerror(errno));
      }
      else {
	if (ifr.ifr_addr.sa_family == AF_INET) {
	  struct sockaddr_in *s = (struct sockaddr_in *)&ifr.ifr_addr;
	  // IP addr is now s->sin_addr
	  char buf[128];
	  inet_ntop(AF_INET, &s->sin_addr, buf, 128);
	  fprintf(stderr, "dev %s has v4 addr %s\n", devName, buf); 
	}
      }
      
      // MAC Address
      if(ioctl(fd,SIOCGIFHWADDR, &ifr) < 0) {
	fprintf(stderr, "dev %s Get SIOCGIFHWADDR failed : %s\n",
		devName,
		strerror(errno));
      }
      else {
	u_char macStr[13];
	printHex((u_char *)&ifr.ifr_hwaddr.sa_data, 6, macStr, 12, false);
	printf("VNIC: ifIndex=%u dev=%s mac=%s up=%u loopback=%u nspid=%u\n", ifIndex, devName, macStr, up, loopback, nspid);
      }
    }
  }
  // ============ repeat using getifaddrs ================
  fprintf(stderr,"repeat using getifaddrs()\n");
  struct ifaddrs *ifaddr;
  if(getifaddrs(&ifaddr) == -1) {
    fprintf(stderr, "getifaddrs() failed : %s\n", strerror(errno));
  }
  else {
    for(struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      if(ifa->ifa_addr == NULL)
	continue;
      int family = ifa->ifa_addr->sa_family;
      char *fam_name = "<unknown>";
      char addr[NI_MAXHOST];
      addr[0] = '\0';
      if(family == AF_INET)
	fam_name = "AF_INET";
      else if(family == AF_INET6)
	fam_name = "AF_INET6";
      else if (family == AF_PACKET)
	fam_name = "AF_PACKET";
      if(family == AF_INET
	 || family == AF_INET6) {
	int s = getnameinfo(ifa->ifa_addr,
			    (family == AF_INET) ?
			    sizeof(struct sockaddr_in) :
			    sizeof(struct sockaddr_in6),
			    addr, NI_MAXHOST,
			    NULL, 0, NI_NUMERICHOST);
	if (s != 0) {
	  fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
	  addr[0] = '\0';
	}
      }
      if(family == AF_PACKET) {
	printHex(((struct sockaddr_ll *)ifa->ifa_addr)->sll_addr, 6, addr, 12, false);
      }
      printf("getifaddrs VNIC: dev=%s fam=%s addr=%s\n", ifa->ifa_name, fam_name, addr);
    }
    freeifaddrs(ifaddr);
  }
}

/*________________---------------------------__________________
  ________________          main             __________________
  ----------------___________________________------------------
*/

int main(int argc, char **argv) {
  if(argc != 2) {
    fprintf(stderr, "usage: %s <nspid>\n", argv[0]);
    exit(-1);
  }
  pid_t nspid = atoi(argv[1]);
  readVNICInterfaces(nspid);
  exit(0);
}
