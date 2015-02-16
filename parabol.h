#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <regex.h>

#ifdef WITH_MYSQL
#include <mysql/mysql.h>
#endif

#include "dist.h"
#include "config.h"
#include "kbuf/kbuf.h"
#include "asio/asio.h"

#ifdef USE_LINUX_SENDFILE
#include <sys/sendfile.h>
#endif

#include "log.h"
#include "net.h"
#include "http.h"
#include "cfg.h"
#include "tracker.h"

#ifdef DEBUG
#define DEBUGF(v...) klogf(LOG_DEBUG, "DEBUG: " v);
#define Kdassert(cond) Kassert(cond)
#else
#define DEBUGF(v...)
#define Kdassert(cond)
#endif

#define Kassert(c) if (!(c)) { klogf(LOG_ERROR, "Assertion (" __STRING(c) ") failed @ " __FILE__ ":%u", __LINE__); exit(1); }
#define Kstrcpy(dest, src) { strncpy((dest), (src), sizeof(dest) - 1); (dest)[sizeof(dest) - 1] = 0; }

#ifdef SHORT_SERVER_VERSION
#define SERVER_VERSION_STR	"parabol"
#else
#define SERVER_VERSION_STR	"parabol/1.1alpha tracker/0.1alpha (" SERVER_DIST ")"
#endif

#ifdef DEBUG
#define SERVER_VERSION		SERVER_VERSION_STR " [debug build]"
#else
#define SERVER_VERSION		SERVER_VERSION_STR
#endif
