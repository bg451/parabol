#include "parabol.h"

extern parabol_config cfg;

peer_entry *torrent_hash[PEER_HASH_SIZE];
peer_entry *peer_hash[PEER_HASH_SIZE];

#ifdef INFOHASH_RESTRICTION
unsigned int infohash_allowed[PEER_HASH_SIZE];
static time_t last_infohash_period;
#endif

unsigned int num_peers, num_torrents, num_seeders, num_leechers;
unsigned int peers_mem_size;

unsigned int announce_count, scrape_count, status_count, peers_count;

static time_t last_period;

static kbuf_ctxh tracker_ctx;
kbuf *syncbuf;

ipmask_entry telia_addrs[] =
{
#include "telia.h"
  { NULL, NULL }
};

void benc_str(kbuf *bencbuf, unsigned char *str)
{
  kbuf_appendf(bencbuf, "%u:%s", strlen(str), str);
}
void benc_int(kbuf *bencbuf, int i)
{
  kbuf_appendf(bencbuf, "i%de", i);
}
void benc_raw(kbuf *bencbuf, unsigned char *data, Ksize_t len)
{
  kbuf_appendf(bencbuf, "%u:", len);
  kbuf_append_data(bencbuf, data, len);
}
void benc_buf(kbuf *bencbuf, kbuf *buf)
{
  benc_raw(bencbuf, kbuf_data(buf), kbuf_idx(buf));
}
void benc_key_raw(kbuf *bencbuf, unsigned char *key, unsigned char *val, Ksize_t val_len)
{
  benc_str(bencbuf, key);
  benc_raw(bencbuf, val, val_len);
}
void benc_key_buf(kbuf *bencbuf, unsigned char *key, kbuf *valbuf)
{
  benc_str(bencbuf, key);
  benc_buf(bencbuf, valbuf);
}
void benc_key_int(kbuf *bencbuf, unsigned char *key, int val)
{
  benc_str(bencbuf, key);
  benc_int(bencbuf, val);
}
void benc_key(kbuf *bencbuf, unsigned char *key, unsigned char *val)
{
  benc_str(bencbuf, key);
  benc_str(bencbuf, val);
}
void benc_out_dict(kbuf *bencbuf, kbuf *outbuf)
{
  kbuf_append_byte(outbuf, 'd');
  kbuf_append_buf(outbuf, bencbuf);
  kbuf_append_byte(outbuf, 'e');
}
void benc_out_list(kbuf *bencbuf, kbuf *outbuf)
{
  kbuf_append_byte(outbuf, 'l');
  kbuf_append_buf(outbuf, bencbuf);
  kbuf_append_byte(outbuf, 'e');
}

void tracker_http_response(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent, unsigned int code, unsigned char *content_type)
{
  net_send(fd);
  http_ent->keep_alive = 0;
  if (http_ent->ver_maj == 0) return;
  kbuf_sprintf(net_ent->sendbuf,
    "HTTP/%u.%u %u %s\r\n"
    "Server: " SERVER_VERSION "\r\n"
    "Content-type: %s\r\n"
    "Connection: close\r\n"
    "Pragma: no-cache\r\n"
    "\r\n",
    http_ent->ver_maj, http_ent->ver_min,
    code, http_status_msg(code),
    content_type);
}
void tracker_benc_response(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent, kbuf *bencbuf)
{
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/plain");
  benc_out_dict(bencbuf, net_ent->sendbuf);
#ifdef DEBUG
  {
    unsigned int i, c;
    
    for (i = 0; i < kbuf_idx(bencbuf); i ++)
    {
      kbuf_get_byte(bencbuf, i, c);
      if (c == 0) kbuf_set_byte(bencbuf, i, '.');
    }
    kbuf_asciiz(bencbuf);
    DEBUGF("sending bencoded response (%u byte(s)): [%s]\n", kbuf_idx(bencbuf), kbuf_data(bencbuf));
  }
#endif
}

unsigned int hash_buf(kbuf *buf)
{
  unsigned int i, c;
  unsigned char curhash[4];
  
  memcpy(curhash, "\xf0\x0f\xc7\xc8", 4);
  for (i = 0; i < kbuf_idx(buf); i ++)
  {
    kbuf_get_byte(buf, i, c);
    curhash[i & 3] ^= c;
  }
  return (curhash[0] << 24) | (curhash[1] << 16) | (curhash[2] << 8) | curhash[3];
}

peer_entry *peer_get(kbuf *peer_id, kbuf *info_hash, unsigned int alloc_new)
{
  peer_entry *peer, *cur;
  unsigned int idx, pidx, i, free_idx;
  
  Kdassert(kbuf_idx(peer_id) == ID_LEN && kbuf_idx(info_hash) == ID_LEN);
  pidx = PEER_HASH_FN(peer_id);
  if (peer_hash[pidx] != NULL &&
      memcmp(peer_hash[pidx]->peer_id, kbuf_data(peer_id), ID_LEN) == 0 &&
      memcmp(peer_hash[pidx]->info_hash, kbuf_data(info_hash), ID_LEN) == 0)
  {
    DEBUGF("found peer in peer_hash");
    return peer_hash[pidx];
  }
  free_idx = (unsigned int)-1;
  idx = PEER_HASH_FN(info_hash); 
  peer = NULL;
  for (i = 0; i < PEER_HASH_SEARCH_DELTA; i ++)
  {
    if ((cur = torrent_hash[idx]) == NULL && free_idx == (unsigned int)-1) free_idx = idx;
    if (cur != NULL && memcmp(cur->info_hash, kbuf_data(info_hash), ID_LEN) == 0)
    {
      peer = cur;
      break;
    }
    idx ++;
    if (idx >= PEER_HASH_SIZE) idx = 0;
  }
  if (i == PEER_HASH_SEARCH_DELTA)
  {
    if (free_idx == (unsigned int)-1) return NULL;
    idx = free_idx;
  } else
  {
    while (peer != NULL)
    {
      if (memcmp(peer->peer_id, kbuf_data(peer_id), ID_LEN) == 0) break;
      peer = peer->next;
    }
  }
  if (peer == NULL && alloc_new == 1)
  {
    peer = malloc(sizeof(peer_entry));
    peers_mem_size += sizeof(peer_entry);
    num_peers ++;
    peer->num_hits = peer->num_seeders = peer->num_leechers = peer->times_completed = 0;
    peer->uploaded = peer->downloaded = 0;
    peer->prev_uploaded = peer->prev_downloaded = 0;
    peer->lastevent = 0;
    peer->last_active = peer->prev_active = (time_t)0;
    peer->is_complete = 0;
    memcpy(peer->peer_id, kbuf_data(peer_id), ID_LEN);
    memcpy(peer->info_hash, kbuf_data(info_hash), ID_LEN);
    peer->hash_idx = idx;
    peer->peer_hash_idx = pidx;
    peer->prev = NULL;
    if ((peer->next = torrent_hash[idx]) != NULL) peer->next->prev = peer;
    torrent_hash[idx] = peer;
    peer_hash[pidx] = peer;
  }
  return peer;
}
void peer_del(peer_entry *peer)
{
  if (peer_hash[peer->peer_hash_idx] == peer) peer_hash[peer->peer_hash_idx] = NULL;
  if (peer->prev != NULL) peer->prev->next = peer->next;
  if (peer->next != NULL) peer->next->prev = peer->prev;
  if (peer == torrent_hash[peer->hash_idx])
  {
    if (peer->next != NULL)
    {
      peer->next->num_seeders = peer->num_seeders;
      peer->next->num_leechers = peer->num_leechers;
      peer->next->times_completed = peer->times_completed;
    }
    torrent_hash[peer->hash_idx] = peer->next;
  }
  num_peers --;
  free(peer);
  peers_mem_size -= sizeof(peer_entry);
}
void scramble_peers(void)
{
  unsigned int i, j, newpeerscount;
  peer_entry *peer, *prevpeer, *headpeer;
  
  DEBUGF("scrambling peers\n");
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = headpeer = torrent_hash[i]) != NULL)
  {
    if ((headpeer->num_seeders + headpeer->num_leechers) > 1) // cfg.tracker.respnum)
    {
      newpeerscount = 0;
      peer = headpeer;
      j = rand() % ((headpeer->num_seeders + headpeer->num_leechers) >> 1);
      while (j > 0 && peer != NULL) { peer = peer->next; j --; }
      if (peer == NULL || peer == headpeer) continue;
      while (peer != NULL && newpeerscount < cfg.tracker.respnum)
      {
        prevpeer = peer;
        peer = peer->next;
        if ((rand() & 7) == 3)
        {
          if (prevpeer->prev != NULL) prevpeer->prev->next = prevpeer->next;
          if (prevpeer->next != NULL) prevpeer->next->prev = prevpeer->prev;
          prevpeer->next = headpeer->next;
          prevpeer->prev = headpeer;
          headpeer->next = prevpeer;
          newpeerscount ++;
        }        
      }
    }
  }
}
unsigned int is_telia(unsigned int ipaddr)
{
  unsigned int i;
  unsigned int cipaddr, cmask;
  i = 0;
  while (telia_addrs[i].ipaddr != NULL)
  {
    cipaddr = ntohl(inet_addr(telia_addrs[i].ipaddr));
    cmask = ntohl(inet_addr(telia_addrs[i].netmask));
    if ((cipaddr & cmask) == (ipaddr & cmask)) return 1;
    i ++;
  }
  return 0;
}
void send_peers(kbuf *outbuf, peer_entry *curpeer, unsigned int send_seeders, unsigned int do_compact, unsigned int only_telia)
{
  peer_entry *peer, *headpeer, *sendpeers[cfg.tracker.respnum];
  unsigned int num_sendpeers, i, j;
  kbuf_ctxh ctx;
  kbuf *buf;
  
  for (i = 0; i < cfg.tracker.respnum; i ++) sendpeers[i] = NULL;
  num_sendpeers = 0;
  peer = headpeer = torrent_hash[curpeer->hash_idx];
  if (headpeer != NULL && (j = headpeer->num_seeders + headpeer->num_leechers) >= cfg.tracker.respnum * 2)
  {
    for (i = rand() % (j - cfg.tracker.respnum); i > 0; i --)
    {
      if ((peer = peer->next) == NULL) peer = headpeer;
    }
  }
  while (num_sendpeers < cfg.tracker.respnum && peer != NULL)
  {
    if (peer != curpeer && (only_telia == 0 || is_telia(peer->ipnum) == 1))
    {
      for (i = 0; i < cfg.tracker.respnum; i ++) if (sendpeers[i] == peer) break;
      if (i == cfg.tracker.respnum && (send_seeders == 1 || peer->is_seeder == 0))
      {
        j = rand() & (cfg.tracker.respnum - 1);
        if (sendpeers[j] == NULL)
        {
          sendpeers[j] = peer;
          num_sendpeers ++;
          peer->num_hits ++;
        }
      }
    }
    peer = peer->next;
  }  
  ctx = kbuf_new_ctx();
  buf = kbuf_init(ctx, 0);
  for (i = 0; i < cfg.tracker.respnum; i ++)
  {
    if (sendpeers[i] != NULL)
    {  
      kbuf_set_idx(buf, 0);
      if (do_compact == 1)
      {
        kbuf_append_data(outbuf, sendpeers[i]->ipraw, sizeof(sendpeers[i]->ipraw));
        kbuf_append_byte(outbuf, (sendpeers[i]->port >> 8) & 0xff);
        kbuf_append_byte(outbuf, sendpeers[i]->port & 0xff);
      } else
      {
        benc_key(buf, "ip", sendpeers[i]->ipstr);
        benc_key_raw(buf, "peer id", sendpeers[i]->peer_id, ID_LEN);
        benc_key_int(buf, "port", sendpeers[i]->port);
        benc_out_dict(buf, outbuf);
      }
      sendpeers[i] = NULL;
    }
  }  
  kbuf_free_ctx(ctx);
}

/*
 * synchronization packet:
 * each entry:
 * [magic 'Khc' 4 bytes]
 * [info hash 20 bytes][peer id 20 bytes]
 * [ip addr 4 bytes][port 2 bytes]
 * [is seeder 1 byte]
 * [padding 1 byte]
 * total entry len: 48 bytes
 */

#define SYNC_ENTRY_LEN		(2 + ID_LEN * 2 + 4 + 2 + 1 + 1)
#define SYNC_ENTRY_MAGIC	"Khc"
#define SYNC_ENTRY_MAGIC_LEN	4

void handle_sync_packet(int fd, net_fd_entry *net_ent, void *dummy)
{
  ssize_t n;
  struct sockaddr_in fromsin;
  socklen_t sin_len;
  kbuf_ctxh ctx;
  kbuf *buf;
  kbuf *peer_id, *info_hash;
  unsigned char ipraw[4];
  unsigned int ipnum, port;
  unsigned int is_seeder;
  peer_entry *peer;
  struct in_addr in;
  
  DEBUGF("got sync packet");
  ctx = kbuf_new_ctx();
  buf = kbuf_init(ctx, cfg.tracker.sync_size + 100);
  sin_len = sizeof(fromsin);
  if ((n = recvfrom(fd, kbuf_data(buf), kbuf_size(buf), 0, (struct sockaddr *)&fromsin, &sin_len)) <= 0)
  {
    kperror("tracker.c:handle_sync_packet():recvfrom()");
    kbuf_free_ctx(ctx);
    return;
  }
  kbuf_set_idx(buf, n);
  DEBUGF("got sync packet from %s:%u", inet_ntoa(fromsin.sin_addr), ntohs(fromsin.sin_port));
  DEBUGF("sync packet is %u bytes", kbuf_idx(buf));
  peer_id = kbuf_init(ctx, ID_LEN);
  info_hash = kbuf_init(ctx, ID_LEN);
  while (kbuf_idx(buf) >= SYNC_ENTRY_LEN)
  {
    if (memcmp(kbuf_data(buf), SYNC_ENTRY_MAGIC, SYNC_ENTRY_MAGIC_LEN) != 0)
    {
      DEBUGF("malformed sync entry, invalid magic %.2x%.2x%.2x%.2x", kbuf_data(buf)[0], kbuf_data(buf)[1], kbuf_data(buf)[2], kbuf_data(buf)[3]);
      break;
    }
    kbuf_consume(buf, SYNC_ENTRY_MAGIC_LEN);
    kbuf_set_data(info_hash, kbuf_data(buf), ID_LEN); kbuf_consume(buf, ID_LEN);
    kbuf_set_data(peer_id, kbuf_data(buf), ID_LEN); kbuf_consume(buf, ID_LEN);
    ipraw[0] = kbuf_eat_byte(buf);
    ipraw[1] = kbuf_eat_byte(buf);
    ipraw[2] = kbuf_eat_byte(buf);
    ipraw[3] = kbuf_eat_byte(buf);
    port = (kbuf_eat_byte(buf) << 8) | kbuf_eat_byte(buf);
    is_seeder = kbuf_eat_byte(buf);
    kbuf_eat_byte(buf); /* eat padding */
    DEBUGF("sync entry: ipraw %.2x%.2x%.2x%.2x port %x is_seeder %u", ipraw[0], ipraw[1], ipraw[2], ipraw[3], port, is_seeder);
    if ((peer = peer_get(peer_id, info_hash, 1)) == NULL)
    {
      klogf(LOG_ERROR, "tracker.c:handle_sync_packet(): peer_get() failed!");
    } else
    {
      peer->last_active = time(NULL);
      peer->lastevent = 0;
      peer->is_local = 0;
      peer->is_seeder = is_seeder;
      memcpy(peer->ipraw, ipraw, 4);
      peer->port = port;
      ipnum = (ipraw[0] << 24) | (ipraw[1] << 16) | (ipraw[2] << 8) | ipraw[3];
      in.s_addr = peer->ipnum = htonl(ipnum);
      Kstrcpy(peer->ipstr, inet_ntoa(in)); 
      DEBUGF("peer->ipstr = '%s' peer->port = %u", peer->ipstr, peer->port);
      DEBUGF("torrent hash idx %u peer hash idx %u", peer->hash_idx, peer->peer_hash_idx);
    }
  }
  if (kbuf_idx(buf) > 0)
  {
    DEBUGF("malformed sync entry, %u byte(s) left", kbuf_idx(buf));
  }
  kbuf_free_ctx(ctx);
}

#ifdef INFOHASH_RESTRICTION
void read_infohash_file(void)
{
  unsigned int i;
  int fd;
  kbuf *readbuf;
  kbuf_ctxh ctx;
  
  for (i = 0; i < PEER_HASH_SIZE; i ++) infohash_allowed[i] = 0;
  if (cfg.tracker.infohash_file == NULL || (fd = open(cfg.tracker.infohash_file, O_RDONLY)) == -1)
  {
    for (i = 0; i < PEER_HASH_SIZE; i ++) infohash_allowed[i] = 1;
    return;    
  }
  ctx = kbuf_new_ctx();
  readbuf = kbuf_init(ctx, ID_LEN);
  kbuf_set_idx(readbuf, ID_LEN);
  while (read(fd, kbuf_data(readbuf), ID_LEN) == ID_LEN)
  {
    infohash_allowed[PEER_HASH_FN(readbuf)] = 1;
  }
  close(fd);
  kbuf_free_ctx(ctx);
}
void init_infohash_restriction(void)
{
  unsigned int i;
  
  last_infohash_period = 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) infohash_allowed[i] = 1;
  //read_infohash_file();
}
#endif

void init_sync(void)
{
  int s;
  struct sockaddr_in sin;
  
  syncbuf = kbuf_init(tracker_ctx, cfg.tracker.sync_size);
  if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 || s >= ASIO_MAX_FDS)
  {
    kperror("tracker.c:init_sync():socket()");
    return;
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(cfg.tracker.sync_port);
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0)
  {
    kperror("tracker.c:init_sync():bind()");
    return;
  }
  net_set_fd(s, NET_FD_RAW, handle_sync_packet, NULL, 0);
  klogf(LOG_INFO, "Tracker sync listening on UDP port %u", cfg.tracker.sync_port);
}
void do_sync(void)
{
  int s;
  struct sockaddr_in sin;
  
  if (kbuf_idx(syncbuf) == 0) return;
  if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
  {
    kperror("tracker.c:do_sync():socket()");
    return;
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = 0;
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0)
  {
    kperror("tracker.c:do_sync():bind()");
    close(s);
    return;
  }
  sin.sin_addr.s_addr = cfg.tracker.sync_addr.s_addr;
  sin.sin_port = htons(cfg.tracker.sync_port);
  DEBUGF("syncing %u bytes", kbuf_idx(syncbuf));
  if (sendto(s, kbuf_data(syncbuf), kbuf_idx(syncbuf), 0, (struct sockaddr *)&sin, sizeof(sin)) != kbuf_idx(syncbuf))
  {
    kperror("tracker.c:do_sync():sendto()");
    close(s);
    return;
  } 
  kbuf_set_idx(syncbuf, 0);
  DEBUGF("sent sync packet");
}
void sync_peer(peer_entry *peer)
{
  kbuf_append_str(syncbuf, SYNC_ENTRY_MAGIC);
  kbuf_append_data(syncbuf, peer->info_hash, ID_LEN);
  kbuf_append_data(syncbuf, peer->peer_id, ID_LEN);
  kbuf_append_data(syncbuf, peer->ipraw, sizeof(peer->ipraw));
  kbuf_append_byte(syncbuf, (peer->port >> 8) & 0xff);
  kbuf_append_byte(syncbuf, peer->port & 0xff);
  kbuf_append_byte(syncbuf, peer->is_seeder & 0xff);
  kbuf_append_byte(syncbuf, 42);
  if (kbuf_idx(syncbuf) >= cfg.tracker.sync_size) do_sync();
}

void tracker_init(void)
{
  unsigned int i;
  
  tracker_ctx = kbuf_new_ctx();
  num_peers = num_torrents = num_seeders = num_leechers = 0;
  peers_mem_size = 0;
  last_period = time(NULL);
  announce_count = scrape_count = status_count = peers_count = 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) torrent_hash[i] = peer_hash[i] = NULL;
  if (cfg.tracker.sync == 1) init_sync();
#ifdef INFOHASH_RESTRICTION
  init_infohash_restriction();
#endif
}
void refresh_peer(peer_entry *peer)
{
  peer_entry *headpeer;
  
  headpeer = peer;
  headpeer->num_seeders = headpeer->num_leechers = 0;
  while (peer != NULL)
  {
    if (peer->is_seeder == 1)
    {
      num_seeders ++;
      headpeer->num_seeders ++;
    } else
    {
      num_leechers ++;
      headpeer->num_leechers ++;
    }
    peer = peer->next;
  }
}
void refresh_peers(void)
{
  unsigned int i;
  peer_entry *peer, *headpeer, *prev;
  
  num_seeders = num_leechers = 0;
  num_torrents = 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = headpeer = torrent_hash[i]) != NULL)
  {
    num_torrents ++;
    headpeer->num_seeders = headpeer->num_leechers = 0;
    while (peer != NULL)
    {
      time_t t;
      
      if (peer->is_seeder == 1)
      {
        num_seeders ++;
        headpeer->num_seeders ++;
      } else
      {
        num_leechers ++;
        headpeer->num_leechers ++;
      }
      prev = peer;
      peer = peer->next;
      t = time(NULL) - prev->last_active;
      if ((prev->lastevent != EVENT_STOPPED && t >= cfg.tracker.timeout) || (prev->lastevent == EVENT_STOPPED && t >= cfg.tracker.stopped_timeout))
      {
        peer_del(prev);
      }
    }  
  }
}

/*
 * GET /peers?[reset]
 * reset: reset ul/dl
 */
void tracker_serve_peers(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  unsigned int i;
  peer_entry *peer;
  unsigned int do_reset, only_stopped;

  peers_count ++;
        
  /*
   * [info hash]:[ip]:[uploaded]:[downloaded]:[last event]\n
   */
  do_reset = (kbuf_table_entry_get(http_ent->args, "reset") != NULL)? 1 : 0;
  only_stopped = (kbuf_table_entry_get(http_ent->args, "stopped") != NULL)? 1 : 0;
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/plain");
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
  {
    while (peer != NULL)
    {
      if (only_stopped == 0 || peer->lastevent == EVENT_STOPPED)
      {
        kbuf_urlencode_data(peer->info_hash, ID_LEN, net_ent->sendbuf);
        kbuf_append_byte(net_ent->sendbuf, ':');
        kbuf_appendf(net_ent->sendbuf, "%s:%llu:%llu:", peer->ipstr, peer->uploaded, peer->downloaded);
        kbuf_appendf(net_ent->sendbuf, "%u", peer->lastevent);
        kbuf_append_byte(net_ent->sendbuf, '\n');
        if (do_reset == 1) peer->uploaded = peer->downloaded = peer->prev_uploaded = peer->prev_downloaded = 0;
      }
      peer = peer->next;
    }
  }
}
void serve_status_raw(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  unsigned int i, do_reset;
  peer_entry *peer;
  
  /*
   * [info hash]:[num seeders]:[num leechers]:[times completed]:[unixtime of last activity]\n
   * ...repeat ad nauseam...
   * the info hash is ID_LEN bytes raw data, the rest are unsigned base10 ints
   */
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/plain");
  do_reset = (kbuf_table_entry_get(http_ent->args, "reset") != NULL)? 1 : 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
  {
    kbuf_urlencode_data(peer->info_hash, ID_LEN, net_ent->sendbuf);
    kbuf_append_byte(net_ent->sendbuf, ':');
    kbuf_appendf(net_ent->sendbuf, "%u:%u:%u:", peer->num_seeders, peer->num_leechers, peer->times_completed);
    if (do_reset == 1) peer->times_completed = 0;
    kbuf_appendf(net_ent->sendbuf, "%u", (unsigned int)peer->last_active);
    kbuf_append_byte(net_ent->sendbuf, '\n');
  }
}
void serve_status_html(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/html");
  kbuf_appendf(net_ent->sendbuf,
    "<HTML>\n"
    "<HEAD><TITLE>Hypercube tracker status</TITLE></HEAD>\n"
    "<BODY>\n"
    "<TABLE BORDER=0>\n"
    "<TR><TD>Statistics</TD><TD>&nbsp;</TD><TD>&nbsp;</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Number of peers/seeders/leechers</TD><TD>%u/%u/%u</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Number of torrents</TD><TD>%u</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Number of announce/scrape/status/peers</TD><TD>%u/%u/%u/%u in %u sec(s)</TD></TR>\n"
    "<TR><TD>Tracker info</TD><TD>&nbsp;</TD><TD>&nbsp;</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Version</TD><TD>" SERVER_VERSION "</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Peer hash table buckets/size</TD><TD>0x%x/%u byte(s)</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Size of peers in memory</TD><TD>%u byte(s)</TD></TR>\n",
    num_peers, num_seeders, num_leechers,
    num_torrents,
    announce_count, scrape_count, status_count, peers_count, (unsigned int)(time(NULL) - last_period),
    PEER_HASH_SIZE, sizeof(torrent_hash),
    peers_mem_size);
  if (kbuf_table_entry_get(http_ent->args, "rate") != NULL)
  {
    unsigned long long total_rate, cur_rate;
    unsigned int i;
    peer_entry *peer;
        
    total_rate = 0;
    for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
    {
      while (peer != NULL)
      {
        unsigned long long delta;
        
        if (peer->lastevent != EVENT_STARTED && peer->lastevent != EVENT_STOPPED && peer->lastevent != EVENT_COMPLETED && peer->prev_active != (time_t)0 && peer->last_active != (time_t)0)
        {
          delta = peer->last_active - peer->prev_active;
          if (delta != 0 && peer->uploaded != 0 && peer->prev_uploaded != 0 && peer->downloaded != 0 && peer->prev_downloaded != 0 && peer->uploaded > peer->prev_uploaded && peer->downloaded > peer->prev_downloaded)
          {
            cur_rate = (peer->uploaded - peer->prev_uploaded + peer->downloaded - peer->prev_downloaded) / delta;
            if (cur_rate < 10485760) total_rate += cur_rate;
          }
        }
        peer = peer->next;
      }
    }
    total_rate /= 1048576;
    kbuf_appendf(net_ent->sendbuf, "<TR><TD>&nbsp;</TD><TD>Total rate (MB/sec)</TD><TD>%llu</TD></TR>\n", total_rate);
  }
  if (kbuf_table_entry_get(http_ent->args, "show_torrents") != NULL)
  {
    kbuf_ctxh ctx;
    kbuf *buf;
    unsigned int i;
    peer_entry *peer;

    ctx = kbuf_new_ctx();
    buf = kbuf_init(ctx, 0);
    
    kbuf_appendf(net_ent->sendbuf,
      "<TR><TD>Torrents</TD><TD><A HREF=\"?\">Hide</A></TD><TD>&nbsp;</TD></TR>\n");
    for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
    {
      kbuf_set_idx(buf, 0);
      kbuf_urlencode_data(peer->info_hash, ID_LEN, buf);
      kbuf_asciiz(buf);
      DEBUGF("html urlenc: last byte %.2x str [%s]", peer->info_hash[ID_LEN - 1], kbuf_data(buf));
      kbuf_appendf(net_ent->sendbuf,
        "<TR><TD>&nbsp;</TD><TD>Info hash</TD><TD>%s</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>Seeders/Leechers/Completed</TD><TD>%u/%u/%u</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>Last activity</TD><TD>%s</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>Peer hash bucket #</TD><TD>0x%x</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>-------------------------------</TD><TD>&nbsp;</TD></TR>\n",
        kbuf_data(buf),
        peer->num_seeders, peer->num_leechers, peer->times_completed, 
        get_date_str(peer->last_active),
        peer->hash_idx);
    }
    kbuf_free_ctx(ctx);
  } else
  {
    kbuf_appendf(net_ent->sendbuf, "<TR><TD>Torrents</TD><TD><A HREF=\"?show_torrents=1\">Show</A></TD><TD>&nbsp;</TD></TR>\n");
  }
  kbuf_appendf(net_ent->sendbuf, "</TABLE>\n</BODY>\n</HTML>\n");

}
/*
 * GET /status?[rate]|[[norefresh]&[raw]&[reset]]
 * norefresh: don't refresh peers list
 * raw: raw format
 * reset: reset completed
 */ 
void tracker_serve_status(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  
  status_count ++;
  
  if (cfg.tracker.sync == 1) do_sync();
  
  if (kbuf_table_entry_get(http_ent->args, "norefresh") == NULL) refresh_peers();
  if (kbuf_table_entry_get(http_ent->args, "raw") != NULL)
  {
    serve_status_raw(fd, http_ent, net_ent);
  } else
  {
    serve_status_html(fd, http_ent, net_ent);
  }
}
void scrape_out(peer_entry *peer, kbuf *outbuf)
{
  kbuf_ctxh ctx;
  kbuf *buf;

  refresh_peer(peer);
  ctx = kbuf_new_ctx();
  buf = kbuf_init(ctx, 0);
  benc_raw(outbuf, peer->info_hash, ID_LEN);
  benc_key_int(buf, "complete", peer->num_seeders);
  benc_key_int(buf, "downloaded", peer->times_completed);
  benc_key_int(buf, "incomplete", peer->num_leechers);
  benc_out_dict(buf, outbuf);
  kbuf_free_ctx(ctx);
}
void tracker_serve_scrape(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  kbuf_ctxh ctx;
  kbuf *info_hash;
  kbuf *outbuf, *filesbuf, *buf;
  peer_entry *peer;
  unsigned int i;
  
#define SCRAPE_ERR(msg)\
  {\
    benc_key(outbuf, "failure reason", (msg));\
    tracker_benc_response(fd, http_ent, net_ent, outbuf);\
    kbuf_free_ctx(ctx);\
    return;\
  }

  scrape_count ++;
  
  ctx = kbuf_new_ctx();
  outbuf = kbuf_init(ctx, 0);
  filesbuf = kbuf_init(ctx, 0);
  buf = kbuf_init(ctx, 0);
  if ((info_hash = kbuf_table_entry_get(http_ent->args, "info_hash")) == NULL)
  {
    for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
    {
      kbuf_set_idx(buf, 0);
      scrape_out(peer, filesbuf);
      peer = peer->next;
    }
  } else
  {
    if (kbuf_idx(info_hash) != ID_LEN) SCRAPE_ERR("invalid info_hash");
    if ((peer = torrent_hash[PEER_HASH_FN(info_hash)]) != NULL)
    {
      /* XXX hash colls */
      kbuf_set_idx(buf, 0);
      scrape_out(peer, filesbuf);
    }
  }
  benc_str(outbuf, "files");
  benc_out_dict(filesbuf, outbuf);
  tracker_benc_response(fd, http_ent, net_ent, outbuf);
  kbuf_free_ctx(ctx);
}
void tracker_serve_announce(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  kbuf_ctxh ctx;
  kbuf *outbuf, *peerbuf, *peersbuf;
  kbuf *info_hash, *peer_id, *ipbuf, *portbuf, *ulbuf, *dlbuf, *leftbuf, *eventbuf;
  kbuf *uabuf;
  int i;
  unsigned int j, c;
  unsigned int curevent, do_compact, only_telia;
  peer_entry *curpeer;
  struct in_addr ipaddr;
  
#define AN_ERR(msg)\
  {\
    kbuf_set_idx(outbuf, 0);\
    benc_key(outbuf, "failure reason", (msg));\
    tracker_benc_response(fd, http_ent, net_ent, outbuf);\
    kbuf_free_ctx(ctx);\
    return;\
  }
    
  announce_count ++;
  
  DEBUGF("tracker: doing announce");
  ctx = kbuf_new_ctx();
  outbuf = kbuf_init(ctx, 0);
  //benc_key_int(outbuf, "interval", cfg.tracker.interval);
  
  if ((info_hash = kbuf_table_entry_get(http_ent->args, "info_hash")) == NULL) AN_ERR("need info_hash");
#ifdef INFOHASH_RESTRICTION
  if (infohash_allowed[PEER_HASH_FN(info_hash)] == 0) AN_ERR("this tracker is for torrents on TPB only");
#endif  
  if ((peer_id = kbuf_table_entry_get(http_ent->args, "peer_id")) == NULL) AN_ERR("need peer_id");
  if ((portbuf = kbuf_table_entry_get(http_ent->args, "port")) == NULL) AN_ERR("need port");
  if ((ulbuf = kbuf_table_entry_get(http_ent->args, "uploaded")) == NULL) AN_ERR("need uploaded");
  if ((dlbuf = kbuf_table_entry_get(http_ent->args, "downloaded")) == NULL) AN_ERR("need downloaded");
  if ((leftbuf = kbuf_table_entry_get(http_ent->args, "left")) == NULL) AN_ERR("need left");
  ipbuf = kbuf_table_entry_get(http_ent->args, "ip");

  eventbuf = kbuf_table_entry_get(http_ent->args, "event");
  curevent = EVENT_NONE;
  if (eventbuf != NULL && kbuf_idx(eventbuf) > 0)
  {
    kbuf_asciiz(eventbuf);
    if (strncasecmp(kbuf_data(eventbuf), "sta", 3) == 0) curevent = EVENT_STARTED;
    else if (strncasecmp(kbuf_data(eventbuf), "com", 3) == 0) curevent = EVENT_COMPLETED;
    else if (strncasecmp(kbuf_data(eventbuf), "sto", 3) == 0) curevent = EVENT_STOPPED;
  }
  if (curevent != EVENT_NONE) DEBUGF("got event %u", curevent);
  if (kbuf_idx(info_hash) != ID_LEN || kbuf_idx(peer_id) != ID_LEN) AN_ERR("invalid info_hash and/or peer_id");
  
  do_compact = (kbuf_table_entry_get(http_ent->args, "compact") != NULL)? 1 : 0;
  only_telia = (kbuf_table_entry_get(http_ent->args, "telia") != NULL)? 1 : 0;
  
  if (curevent == EVENT_STOPPED || curevent == EVENT_COMPLETED)
  {
    if ((curpeer = peer_get(peer_id, info_hash, 0)) == NULL)
    {
      DEBUGF("event %u for unknown peer, ignoring", curevent);
      benc_str(outbuf, "peers");
      kbuf_appendf(outbuf, "le");
      tracker_benc_response(fd, http_ent, net_ent, outbuf);
      kbuf_free_ctx(ctx);
      return;
    }
  } else
  {
    if ((curpeer = peer_get(peer_id, info_hash, 1)) == NULL) AN_ERR("too many peers");
  }
  if (curevent == EVENT_STARTED || curpeer->lastevent == EVENT_STARTED)
  {
    benc_key_int(outbuf, "interval", cfg.tracker.init_interval);
  } else
  {
    benc_key_int(outbuf, "interval", cfg.tracker.interval);
  }
  curpeer->is_local = 1;
  j = 0;
  for (i = 0; i < kbuf_idx(portbuf); i ++)
  {
    kbuf_get_byte(portbuf, i, c);
    if (c < '0' || c > '9') break;
    j *= 10;
    j += c - '0';
  }
  /* causes problems for some clients if (j > 0xffff || j < 0x400) AN_ERR("invalid port"); */
  curpeer->port = j;

  if (ipbuf != NULL && kbuf_idx(ipbuf) > 1)
  {
    kbuf_asciiz(ipbuf);
    if ((ipaddr.s_addr = inet_addr(kbuf_data(ipbuf))) == INADDR_NONE)
    {
      ipbuf = NULL;
    } else
    {
      j = ntohl(ipaddr.s_addr);
      if ((j >= 0x0a000000 && j <= 0x0affffff) ||
          (j >= 0xac100000 && j <= 0xac1fffff) ||
          (j >= 0xc0a80000 && j <= 0xc0a8ffff)) ipbuf = NULL;
    }
  }
  if (ipbuf == NULL || kbuf_idx(ipbuf) <= 1)
  {
    ipbuf = kbuf_init(ctx, 0);
    kbuf_clone(ipbuf, net_ent->peerbuf);
    if ((i = kbuf_chr(ipbuf, ':')) != -1) kbuf_set_idx(ipbuf, i);
  }
  kbuf_asciiz(ipbuf);
  Kstrcpy(curpeer->ipstr, kbuf_data(ipbuf));
  j = curpeer->ipnum = ntohl(inet_addr(curpeer->ipstr));
  curpeer->ipraw[0] = (j >> 24) & 0xff;
  curpeer->ipraw[1] = (j >> 16) & 0xff;
  curpeer->ipraw[2] = (j >> 8) & 0xff;
  curpeer->ipraw[3] = j & 0xff;

  curpeer->prev_active = curpeer->last_active;
  curpeer->last_active = time(NULL);
  
#if 0
  if (num_peers == 1000000)
  {
    FILE *f;

    if (cfg.tracker.statslog != NULL && (f = fopen(cfg.tracker.statslog, "a+")) != NULL)
    {
      fprintf(f, "!!! Reached 1 million peers @ %s: %s %u\n", get_now_date_str(), curpeer->ipstr, curpeer->port);
      fflush(f);
      fclose(f);
    }
  }
#endif

  j = 0;
  for (i = 0; i < kbuf_idx(leftbuf); i ++)
  {
    kbuf_get_byte(leftbuf, i, c);
    if (c < '0' || c > '9') break;
    if (j >= 0x19999999) { j = (unsigned int)-1; break; }
    j *= 10;
    j += c - '0';
  }
  DEBUGF("got left %u", j);
  curpeer->is_seeder = (j == 0)? 1 : 0;

  curpeer->prev_uploaded = curpeer->uploaded;
  curpeer->uploaded = 0;
  for (i = 0; i < kbuf_idx(ulbuf); i ++)
  {
    kbuf_get_byte(ulbuf, i, c);
    if (c < '0' || c > '9') break;
    curpeer->uploaded *= 10;
    curpeer->uploaded += c - '0';
  }
  curpeer->prev_downloaded = curpeer->downloaded;
  curpeer->downloaded = 0;
  for (i = 0; i < kbuf_idx(dlbuf); i ++)
  {
    kbuf_get_byte(dlbuf, i, c);
    if (c < '0' || c > '9') break;
    curpeer->downloaded *= 10;
    curpeer->downloaded += c - '0';
  }
  DEBUGF("ul %llu dl %llu", curpeer->uploaded, curpeer->downloaded);
  
  curpeer->lastevent = curevent;

  if ((uabuf = kbuf_table_entry_get(http_ent->headers, "User-Agent")) != NULL)
  {
    if (kbuf_idx(uabuf) >= 12 && memcmp(kbuf_data(uabuf), "Ratio Fucker", 12) == 0)
    {
      kbuf_asciiz(net_ent->peerbuf);
      klogf(LOG_INFO, "Cheater: Ratio Fucker request from %s", kbuf_data(net_ent->peerbuf));
      curpeer->uploaded = 0;
      curpeer->downloaded = 0;
    }
  }
  
  i = 0;
  peerbuf = kbuf_init(ctx, 0);
  peersbuf = kbuf_init(ctx, 0);
  
  if (curevent == EVENT_COMPLETED)
  {
    torrent_hash[curpeer->hash_idx]->times_completed ++;
    curpeer->is_complete = 1;
  }
  send_peers(peersbuf, curpeer, (curpeer->is_seeder == 1)? 0 : 1, do_compact, only_telia);
  if (do_compact == 1)
  {
    benc_key_buf(outbuf, "peers", peersbuf);
  } else
  {
    benc_str(outbuf, "peers");
    benc_out_list(peersbuf, outbuf);
  }
  tracker_benc_response(fd, http_ent, net_ent, outbuf);
  if (curevent != EVENT_STOPPED && cfg.tracker.sync == 1) sync_peer(curpeer);
  
  kbuf_free_ctx(ctx);
}
void update_stats(void)
{
#ifdef WITH_MYSQL
  MYSQL sql_conn;
  kbuf *buf, *sqlbuf;
  kbuf_ctxh ctx;
  unsigned int i;
  peer_entry *peer, *headpeer;
    
  if (cfg.tracker.sql_stats == 0) return;
  DEBUGF("doing update_stats()");
  if (fork() != 0) return;
  
  signal(SIGALRM, exit);
  alarm(cfg.tracker.period);
  DEBUGF("in update_stats() child");
  //while (1) sleep(1);
  mysql_init(&sql_conn);
  if (mysql_real_connect(&sql_conn, cfg.tracker.sql_host, cfg.tracker.sql_user, cfg.tracker.sql_pass, cfg.tracker.sql_db, 0, NULL, 0) == NULL)
  {
    klogf(LOG_ERROR, "Couldn't connect to MySQL server: %s", mysql_error(&sql_conn));
    exit(1);
  }
  ctx = kbuf_new_ctx();
  buf = kbuf_init(ctx, 0);
  sqlbuf = kbuf_init(ctx, 0);
  kbuf_sprintf(sqlbuf, "UPDATE hc_stats SET seeders='%u', leechers='%u', num_torrents='%u'", num_seeders, num_leechers, num_torrents);
  kbuf_asciiz(sqlbuf);
  DEBUGF("sql query (hc_stats) [%s]", kbuf_data(sqlbuf));
  if (mysql_real_query(&sql_conn, kbuf_data(sqlbuf), kbuf_idx(sqlbuf)) != 0)
  {
      DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
  }
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = headpeer = torrent_hash[i]) != NULL)
  {
    kbuf_set_idx(buf, 0);
    kbuf_set_idx(sqlbuf, 0);
    kbuf_base64encode_data(peer->info_hash, ID_LEN, buf);
    kbuf_asciiz(buf);
    kbuf_sprintf(sqlbuf, "UPDATE torrents SET seeders='%u', leechers='%u', last_active='%u' WHERE info_hash='%s'", peer->num_seeders, peer->num_leechers, peer->last_active, kbuf_data(buf));
    kbuf_asciiz(sqlbuf);
    DEBUGF("sql query (torrents) [%s]", kbuf_data(sqlbuf));
    if (mysql_real_query(&sql_conn, kbuf_data(sqlbuf), kbuf_idx(sqlbuf)) != 0)
    {
      DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
    }
    while (peer != NULL)
    {
      if (peer->is_complete == 1)
      {
        peer->is_complete = 0;
        kbuf_set_idx(buf, 0);
        kbuf_set_idx(sqlbuf, 0);
        kbuf_base64encode_data(peer->info_hash, ID_LEN, buf);
        kbuf_asciiz(buf);
        kbuf_sprintf(sqlbuf, "UPDATE torrents SET num_downloads=num_downloads+1 WHERE info_hash='%s'", kbuf_data(buf));
        kbuf_asciiz(sqlbuf);
        DEBUGF("sql query (torrents complete) [%s]", kbuf_data(sqlbuf));
        if (mysql_real_query(&sql_conn, kbuf_data(sqlbuf), kbuf_idx(sqlbuf)) != 0)
        {
          DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
        }
      } else if (peer->lastevent == EVENT_STOPPED)
      {
        kbuf_set_idx(buf, 0);
        kbuf_set_idx(sqlbuf, 0);
        kbuf_base64encode_data(peer->info_hash, ID_LEN, buf);
        kbuf_asciiz(buf);
        kbuf_sprintf(sqlbuf, "UPDATE users SET uploaded=uploaded+'%llu', downloaded=downloaded+'%llu' WHERE ip='%u'", peer->uploaded, peer->downloaded, peer->ipnum); 
        kbuf_asciiz(sqlbuf);
        DEBUGF("sql query (peers) [%s]", kbuf_data(sqlbuf));
        if (mysql_real_query(&sql_conn, kbuf_data(sqlbuf), kbuf_idx(sqlbuf)) != 0)
        {
          DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
        } else
        {
          peer->uploaded = peer->downloaded = 0;
          peer->prev_uploaded = peer->prev_downloaded = 0;
        }
        peer->uploaded = peer->downloaded = 0;
        peer->prev_uploaded = peer->prev_downloaded = 0;
        
      }
      peer = peer->next;
    }
  }  
  kbuf_free_ctx(ctx);
  exit(0);
#endif
}
void tracker_periodic(void)
{
  time_t t;
  FILE *f;
  
  //scramble_peers();
#ifdef INFOHASH_RESTRICTION
  if ((t = time(NULL) - last_infohash_period) >= cfg.tracker.infohash_interval) 
  {
    read_infohash_file();
    last_infohash_period = time(NULL);
  }
#endif
  if ((t = time(NULL) - last_period) < cfg.tracker.period) return;
  if (cfg.tracker.statslog != NULL && (f = fopen(cfg.tracker.statslog, "a+")) != NULL)
  { 
    fprintf(f, "%s %u %u %u %u / %u\n", get_now_date_str(), announce_count, scrape_count, status_count, peers_count, (unsigned int)t);
    fflush(f);
    fclose(f);
  }
  announce_count = scrape_count = status_count = peers_count = 0;
  refresh_peers();
  update_stats();
  last_period = time(NULL);
}
