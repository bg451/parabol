//#define DEBUG

#define CFG_FILE		"/var/hctracker/parabol.cfg"

#define LISTEN_BACKLOG		65535
#define SOCKET_TIMEOUT		15
#define MAX_LINE_LEN		(BUF_SIZE * 2)
#define BUF_SIZE		4096
#define SEND_BUF_SIZE		16384
#define HTTP_MAX_HEADERS	16
#define HTTP_MAX_CONTENT_LEN	32768
#define CGI_MIME_TYPE		"application/x-cgi"
#define CGI_DEFAULT_PATH	"/usr/local/bin:/usr/xpg4/bin:/usr/ccs/bin:/bin:/usr/bin:/sbin:/usr/sbin:/usr/ucb/bin"
#define GZIP_SUFFIX		"HCgz"

/*
#define NUM_RESP_PEERS			50
#define ANNOUNCE_INTERVAL		420
#define PEER_TIMEOUT			(ANNOUNCE_INTERVAL * 2)
#define TRACKER_PERIOD_INTERVAL		15
*/
