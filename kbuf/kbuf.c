#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>

#include "kbuf.h"

kbuf_ctx *ctx_hash[KBUF_CTX_HASH_SIZE];
unsigned int ctx_hash_initialized = 0;
unsigned int prng_initialized = 0;

//#define RANDFUNC vanilla_rand /* XXX */
#define RANDFUNC randfunc_inc

//#define KBUF_DEBUG

#define K_REALSIZE(size)	(((size) <= GRAIN_SIZE && (size) != 0)? (size) : (((size) | (GRAIN_SIZE - 1)) + 1))
#define CTX_HASH_FN(hnd)	((hnd) & (KBUF_CTX_HASH_SIZE - 1))

#ifdef KBUF_TEST
#define KBUF_DEBUG
#endif

#ifdef KBUF_DEBUG
void dump_all_ctxs(void)
{
#if 0
  kbuf_ctx *ctx;
  
  printf("dumping ctxs head %.8x:\n", (unsigned int)ctx_head);
  ctx = ctx_head;
  while (ctx != NULL)
  {
    printf("  ctx @ %.8x; handle %.8x bufs %.8x\n", (unsigned int)ctx, (unsigned int)ctx->hnd, (unsigned int)ctx->head);
    ctx = ctx->next;
  }
  printf("end of dump\n");
#endif
}
#endif
unsigned int vanilla_rand(void)
{
  if (prng_initialized == 0)
  {
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16));
    prng_initialized = 1;
  }
  return rand();
}
static unsigned int cur_ctx;
unsigned int randfunc_inc(void)
{
  if (prng_initialized == 0)
  {
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    cur_ctx = tv.tv_usec;
    prng_initialized = 1;
  }
  return cur_ctx ++; 
}
void kbuf_panic(unsigned char *file, unsigned int line, unsigned char *from_file, unsigned int from_line, unsigned char *format, ...)
{
  unsigned char msg[2048];
  
  va_list va;
  if (from_file != NULL)
  {
    snprintf(msg, sizeof(msg) - 1, "Kbuf PANIC @ %s:%u (from %s:%u): ", file, line, from_file, from_line); msg[sizeof(msg) - 1] = 0;
  } else
  {
    snprintf(msg, sizeof(msg) - 1, "Kbuf PANIC @ %s:%u: ", file, line); msg[sizeof(msg) - 1] = 0;
  }
  write(2, msg, strlen(msg));
  va_start(va, format);
  vsnprintf(msg, sizeof(msg) - 1, format, va); msg[sizeof(msg) - 1] = 0;
  va_end(va);
  write(2, msg, strlen(msg));
  write(2, "\n", 1);
  _exit(1);
}
kbuf_ctx *kbuf_find_ctx(kbuf_ctxh hnd)
{
  kbuf_ctx *cur;
  
  if (ctx_hash_initialized == 0)
  {
    unsigned int i;
    
    for (i = 0; i < KBUF_CTX_HASH_SIZE; i ++) ctx_hash[i] = NULL;
    ctx_hash_initialized = 1;
  }
  cur = ctx_hash[CTX_HASH_FN(hnd)];
  while (cur != NULL) { if (cur->hnd == hnd) return cur; cur = cur->next; }
  return NULL;
}
kbuf_ctxh kbuf_new_ctx(void)
{
  kbuf_ctx *new;
  unsigned int idx;
  
  new = malloc(sizeof(*new));
  Kbuf_ASSERT(new != NULL);
  do
  {
    new->hnd = RANDFUNC();
  } while (kbuf_find_ctx(new->hnd) != NULL || new->hnd == Kbuf_INVALID_CTX);
  new->head = NULL;
  new->prev = NULL;
  new->next = ctx_hash[idx = CTX_HASH_FN(new->hnd)];
  if (new->next != NULL) new->next->prev = new;
  ctx_hash[idx] = new;
  return new->hnd;
}
kbuf *kbuf_init(kbuf_ctxh ctxh, Ksize_t _size)
{
  Ksize_t size;
  kbuf *new;
  kbuf_ctx *ctx;
  
  if ((ctx = kbuf_find_ctx(ctxh)) == NULL) Kbuf_PANIC("kbuf_init(): Invalid ctx %.8x", ctxh);
  size = K_REALSIZE(_size); 
#ifdef KBUF_DEBUG
  printf("DEBUG: req size %.8x, final size %.8x\n", _size, size);
#endif
  Kbuf_ASSERT(size >= _size);
  new = malloc(sizeof(kbuf));
  Kbuf_ASSERT(new != NULL);
  new->in_use = 1;
  new->size = size;
  new->idx = 0;
  new->prev = NULL;
  new->next = ctx->head;
  new->head = malloc(size);
  Kbuf_ASSERT(new->head != NULL);
  if (ctx->head != NULL) ctx->head->prev = new;
  ctx->head = new;
#ifdef KBUF_DEBUG
  memset(new->head, 'A', new->size);
#endif
  return new;
}
void kbuf_set_size(kbuf *buf, Ksize_t _size)
{
  Ksize_t size;
  
  Kbuf_dASSERT(buf != NULL);
  size = K_REALSIZE(_size);
  Kbuf_ASSERT(size >= _size);
  if (size == buf->size) return;
  buf->head = realloc(buf->head, size);
  Kbuf_ASSERT(buf->head != NULL);
  buf->size = size;
  if (buf->idx > size) buf->idx = size;
  return;
}
void kbuf_consume(kbuf *buf, Ksize_t len)
{
  Kbuf_dASSERT(buf != NULL);
  if (len == 0) return;
  Kbuf_ASSERT(buf->idx >= len && buf->idx <= buf->size);
  memcpy(buf->head, buf->head + len, buf->idx - len);
  buf->idx -= len;
  if (len >= GRAIN_SIZE) kbuf_set_size(buf, buf->idx);
  return;
}
unsigned char kbuf_eat_byte(kbuf *buf)
{
  unsigned char ret;
  
  Kbuf_dASSERT(buf != NULL);
  Kbuf_ASSERT(buf->idx > 0 && buf->idx <= buf->size);
  ret = *buf->head;
  memcpy(buf->head, buf->head + 1, buf->idx - 1);
  buf->idx --;
  return ret;
}
void kbuf_set_data(kbuf *buf, unsigned char *data, Ksize_t len)
{
  Kbuf_dASSERT(buf != NULL && data != NULL);
  if (len > buf->size) kbuf_set_size(buf, len);
  memcpy(buf->head, data, len);
  buf->idx = len;
  return;
}
void kbuf_vsprintf(kbuf *buf, unsigned char *format, va_list va)
{
  Kssize_t n;
    
  Kbuf_dASSERT(buf != NULL && format != NULL);
  if ((n = vsnprintf(buf->head, buf->size, format, va)) >= buf->size && n >= 0)
  {
    Kbuf_ASSERT((n + 1) > n);
    kbuf_set_size(buf, n + 1);
    n = vsnprintf(buf->head, buf->size, format, va);
  }
  Kbuf_ASSERT(n >= 0);
  buf->idx = n;
  return;
}
void kbuf_sprintf(kbuf *buf, unsigned char *format, ...)
{
  va_list va;
  
  va_start(va, format);
  kbuf_vsprintf(buf, format, va);
  va_end(va);
  return;
}
void kbuf_appendf(kbuf *buf, unsigned char *format, ...)
{
  kbuf_ctxh ctx;
  kbuf *appendbuf;
  va_list va;
  
  ctx = kbuf_new_ctx();
  appendbuf = kbuf_init(ctx, 0);
  va_start(va, format);
  kbuf_vsprintf(appendbuf, format, va);
  va_end(va);
  kbuf_append_buf(buf, appendbuf); 
  kbuf_free_ctx(ctx);
}
void kbuf_append_data(kbuf *buf, unsigned char *data, Ksize_t len)
{
  Kbuf_dASSERT(buf != NULL && data != NULL);
  Kbuf_ASSERT(buf->idx + len >= buf->idx && buf->idx <= buf->size);
  if (buf->idx + len >= buf->size) kbuf_set_size(buf, buf->idx + len);
  memcpy(buf->head + buf->idx, data, len); buf->idx += len;
  return;
}
void kbuf_append_byte(kbuf *buf, unsigned char b)
{
  Kbuf_dASSERT(buf != NULL);
  Kbuf_ASSERT(buf->idx + 1 > buf->idx && buf->idx <= buf->size);
  if (buf->idx + 1 >= buf->size) kbuf_set_size(buf, buf->idx + 1);
  buf->head[buf->idx ++] = b;
  return;
}
int kbuf_chr(kbuf *buf, unsigned char b)
{
  unsigned char *p;
  
  Kbuf_dASSERT(buf != NULL);
  if ((p = memchr(buf->head, b, buf->idx)) == NULL) return -1;
  return (int)(p - buf->head);
}
void kbuf_asciiz(kbuf *buf)
{
  Kbuf_dASSERT(buf != NULL);
  Kbuf_ASSERT(buf->idx + 1 > buf->idx && buf->idx <= buf->size);
  if (buf->idx == buf->size) kbuf_set_size(buf, buf->idx + 1);
  buf->head[buf->idx] = 0;
  return;
}
void kbuf_free(kbuf_ctxh ctxh, kbuf *buf)
{
  kbuf_ctx *ctx;
  kbuf *cur;
  
  Kbuf_dASSERT(buf != NULL);
  if ((ctx = kbuf_find_ctx(ctxh)) == NULL) Kbuf_PANIC("kbuf_free(): Invalid ctx %.8x", ctxh);
  cur = ctx->head;
  while (cur != buf && cur != NULL) cur = cur->next;
  if (cur == NULL) Kbuf_PANIC("kbuf_free(): Unknown kbuf %.8x", (unsigned int)buf);
#ifdef KBUF_DEBUG
  printf("DEBUG: freeing buf %.8x\n", (unsigned int)cur);
#endif
  Kbuf_ASSERT(cur->in_use == 1 && cur->head != NULL);
  cur->in_use = 0;
  if (cur->prev != NULL) cur->prev->next = cur->next;
  if (cur->next != NULL) cur->next->prev = cur->prev;
  if (cur == ctx->head) ctx->head = cur->next;
  cur->prev = cur->next = NULL;
  cur->idx = (unsigned int)-1;
#ifdef KBUF_DEBUG
  memset(cur->head, 'F', cur->size);
#else
  //memset(cur->head, 'F', (cur->size > GRAIN_SIZE)? GRAIN_SIZE : cur->size);
#endif  
  cur->size = 0;
  Kfree(cur->head); cur->head = NULL;
  free(cur);
}
void _kbuf_free_ctx(kbuf_ctxh ctxh, unsigned char *from_file, unsigned int from_line)
{
  kbuf_ctx *ctx;
  kbuf *cur, *prev;
  unsigned int idx;
  
  if (ctxh == Kbuf_INVALID_CTX) return;
  if ((ctx = kbuf_find_ctx(ctxh)) == NULL) Kbuf_PANIC_FROM("kbuf_free_ctx(): Invalid ctx %.8x", ctxh);
  cur = ctx->head;
  while (cur != NULL)
  {
    prev = cur;
    cur = cur->next;
    Kbuf_ASSERT(prev->in_use == 1 && prev->head != NULL);
    prev->in_use = 0;
    prev->prev = prev->next = NULL;
    prev->idx = (unsigned int)-1;
#ifdef KBUF_DEBUG
    printf("DEBUG: prev %.8x prev->size %.8x\n", (unsigned int)prev, prev->size);
    memset(prev->head, 'G', prev->size);
#endif    
    //memset(prev->head, 'F', (prev->size > GRAIN_SIZE)? GRAIN_SIZE : prev->size);
    prev->size = 0;
    Kfree(prev->head); prev->head = NULL;
    free(prev);
  }
  ctx->head = NULL;
  if (ctx->prev != NULL) ctx->prev->next = ctx->next;
  if (ctx->next != NULL) ctx->next->prev = ctx->prev;
  if (ctx == ctx_hash[idx = CTX_HASH_FN(ctxh)]) ctx_hash[idx] = ctx->next;
#ifdef KBUF_DEBUG
  memset(ctx, 'C', sizeof(kbuf_ctx));
#endif
  free(ctx);
}
kbuf_table *kbuf_table_init(kbuf_ctxh ctxh, unsigned int type)
{
  kbuf *tblbuf;
  kbuf_table *ret;
  
  tblbuf = kbuf_init(ctxh, sizeof(kbuf_table));
  Kbuf_dASSERT(tblbuf != NULL);
  kbuf_set_idx(tblbuf, sizeof(kbuf_table));
  ret = (kbuf_table *)kbuf_data(tblbuf);
  ret->head = ret->tail = NULL;
  ret->type = type;
  ret->ctxh = ctxh;
  return ret;
}
kbuf_table_entry *kbuf_table_entry_add(kbuf_ctxh ctxh, kbuf_table *tbl, unsigned char *key, kbuf *data)
{
  kbuf *entbuf;
  kbuf_table_entry *new;
  
  Kbuf_dASSERT(tbl != NULL && key != NULL && data != NULL);
  Kbuf_ASSERT(ctxh == tbl->ctxh);
  if (kbuf_find_ctx(ctxh) == NULL) Kbuf_PANIC("kbuf_table_entry_add(): Invalid ctx %.08x", ctxh);
  if ((new = kbuf_table_entry_find(tbl, key)) != NULL)
  {
    kbuf_clone(new->data, data);
    return new;
  }
  entbuf = kbuf_init(ctxh, sizeof(kbuf_table_entry));
  Kbuf_dASSERT(entbuf != NULL);
  kbuf_set_idx(entbuf, sizeof(kbuf_table_entry));
  new = (kbuf_table_entry *)kbuf_data(entbuf);
  new->key = kbuf_init(ctxh, 0);
  kbuf_strcpy(new->key, key);
  kbuf_append_byte(new->key, 0);
  new->data = kbuf_init(ctxh, kbuf_idx(data));
  kbuf_clone(new->data, data);
  new->prev = tbl->tail;
  new->next = NULL;
  if (tbl->head == NULL) 
  {
    tbl->head = new;
  } else
  {
    tbl->tail->next = new;
  }
  tbl->tail = new;
  return new;
}
kbuf_table_entry *kbuf_table_entry_add_buf(kbuf_ctxh ctxh, kbuf_table *tbl, kbuf *key, kbuf *data)
{
  kbuf *entbuf;
  kbuf_table_entry *new;

  Kbuf_dASSERT(tbl != NULL && key != NULL && data != NULL);
  Kbuf_ASSERT(tbl->type == KBUF_TABLE_BIN);
  Kbuf_ASSERT(ctxh == tbl->ctxh);
  if (kbuf_find_ctx(ctxh) == NULL) Kbuf_PANIC("kbuf_table_entry_add(): Invalid ctx %.08x", ctxh);
  entbuf = kbuf_init(ctxh, sizeof(kbuf_table_entry));
  Kbuf_dASSERT(entbuf != NULL);
  kbuf_set_idx(entbuf, sizeof(kbuf_table_entry));
  new = (kbuf_table_entry *)kbuf_data(entbuf);
  new->key = kbuf_init(ctxh, kbuf_idx(key));
  kbuf_clone(new->key, key);
  kbuf_append_byte(new->key, 0);
  new->data = kbuf_init(ctxh, kbuf_idx(data));
  kbuf_clone(new->data, data);
  new->prev = tbl->tail;
  new->next = NULL;
  if (tbl->head == NULL) 
  {
    tbl->head = new;
  } else
  {
    tbl->tail->next = new;
  }
  tbl->tail = new;
  return new;
}
kbuf_table_entry *kbuf_table_entry_add_str(kbuf_ctxh ctxh, kbuf_table *tbl, unsigned char *key, unsigned char *data)
{
  kbuf *buf;
  kbuf_ctxh ctx;
  kbuf_table_entry *ret;
  
  ctx = kbuf_new_ctx();
  buf = kbuf_init(ctx, 0);
  kbuf_strcpy(buf, data); kbuf_append_byte(buf, 0);
  ret = kbuf_table_entry_add(ctxh, tbl, key, buf);
  kbuf_free_ctx(ctx);
  return ret;
}
kbuf_table_entry *kbuf_table_entry_find(kbuf_table *tbl, unsigned char *key)
{
  int (*cmpfn)();
  kbuf_table_entry *ent;
  
  Kbuf_dASSERT(tbl != NULL && key != NULL);
  Kbuf_ASSERT(tbl->type == KBUF_TABLE_NOCASE || tbl->type == KBUF_TABLE_CASE);
  cmpfn = (tbl->type == KBUF_TABLE_CASE)? strcmp : strcasecmp;
  ent = tbl->head;
  while (ent != NULL)
  {
    if (cmpfn(kbuf_data(ent->key), key) == 0) return ent;
    ent = ent->next;
  }
  return NULL;
}
kbuf *kbuf_table_entry_get(kbuf_table *tbl, unsigned char *key)
{
  kbuf_table_entry *ent;
  
  if ((ent = kbuf_table_entry_find(tbl, key)) == NULL) return NULL;
  return ent->data;
}
unsigned char *kbuf_table_entry_get_str(kbuf_table *tbl, unsigned char *key)
{
  kbuf *buf;
  
  if ((buf = kbuf_table_entry_get(tbl, key)) == NULL) return NULL;
  kbuf_asciiz(buf);
  return kbuf_data(buf); 
}

void kbuf_urlencode_data(unsigned char *data, Ksize_t len, kbuf *outbuf)
{
  unsigned int i;
  unsigned int c;

  for (i = 0; i < len; i ++)
  {
    unsigned char hexchars[] = "0123456789ABCDEF";

    c = data[i];
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= '<'))
    {
      kbuf_append_byte(outbuf, c);
    } else
    {
      kbuf_append_byte(outbuf, '%');
      kbuf_append_byte(outbuf, hexchars[(c >> 4) & 0xf]);
      kbuf_append_byte(outbuf, hexchars[c & 0xf]);
    }
  }
}
void kbuf_base64encode_data(unsigned char *data, Ksize_t len, kbuf *outbuf)
{
  Ksize_t rem;
  unsigned char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  rem = len;
  while (rem > 2)
  {
    kbuf_append_byte(outbuf, b64chars[data[0] >> 2]);
    kbuf_append_byte(outbuf, b64chars[((data[0] & 0x03) << 4) + (data[1] >> 4)]);
    kbuf_append_byte(outbuf, b64chars[((data[1] & 0x0f) << 2) + (data[2] >> 6)]);
    kbuf_append_byte(outbuf, b64chars[data[2] & 0x3f]);
    data += 3;
    rem -= 3;
  }
  if (rem != 0)
  {
    kbuf_append_byte(outbuf, b64chars[data[0] >> 2]);
    if (rem > 1)
    {
      kbuf_append_byte(outbuf, b64chars[((data[0] & 0x03) << 4) + (data[1] >> 4)]);
      kbuf_append_byte(outbuf, b64chars[((data[1] & 0x0f) << 2)]);
      kbuf_append_byte(outbuf, '=');
    } else
    {
      kbuf_append_byte(outbuf, b64chars[((data[0] & 0x03) << 4)]);
      kbuf_append_byte(outbuf, '=');
      kbuf_append_byte(outbuf, '=');
    }
  }
}

#ifdef KBUF_TEST
int main(int argc, char *argv[])
{
  kbuf_ctxh ctx;
  kbuf *buf, *buf2;
  int i;
  kbuf_table *tbl;
  kbuf_table_entry *ent;
  
  printf("kbuf_new_ctx()\n");
  ctx = kbuf_new_ctx();
  printf(" = %.8x\n", (unsigned int)ctx);
  printf("kbuf_new_ctx() second = %.8x\n", (unsigned int)kbuf_new_ctx());
  dump_all_ctxs();
  
  buf = kbuf_init(ctx, 0);
  kbuf_strcpy(buf, "blutti");
  printf("kbuf_table_init() =\n");
  tbl = kbuf_table_init(ctx, 0);
  printf("  %.08x\n", (unsigned int)tbl);
  printf("kbuf_table_entry_add() =\n");
  ent = kbuf_table_entry_add(ctx, tbl, "foobar", buf);
  printf("  %.08x\n", (unsigned int)ent);
  printf("[%s]\n", kbuf_data(ent->key));
  kbuf_strcpy(buf, "fnutti");
  ent = kbuf_table_entry_add(ctx, tbl, "foobar2", buf);
  printf("  next = %.08x prev = %.08x head = %.08x tail = %.08x\n", (unsigned int)ent->next, (unsigned int)ent->prev, (unsigned int)tbl->head, (unsigned int)tbl->tail);
  printf("kbuf_table_entry_get(..., \"foobar\")\n");
  buf2 = kbuf_table_entry_get(tbl, "foobar");
  if (buf2 != NULL)
  {
    kbuf_asciiz(buf2);
    printf("  [%s]\n", kbuf_data(buf2)); 
  }
  printf("kbuf_table_entry_get(..., \"foobar2\")\n");
  buf2 = kbuf_table_entry_get(tbl, "foobar2");
  if (buf2 != NULL)
  {
    kbuf_asciiz(buf2);
    printf("  [%s]\n", kbuf_data(buf2)); 
  }
  
#if 1
  printf("kbuf_init(0x242)\n");
  buf = kbuf_init(ctx, 0x242);
  printf(" = %.8x\n", (unsigned int)buf);
  //printf("kbuf_init(0xffffffff)\n");
  //kbuf_init(ctx, 0xffffffff);
  kbuf_strcpy(buf, "foobar blutti");
  kbuf_append_str(buf, " fnutti");
  kbuf_asciiz(buf);
  printf("[%s]\n", kbuf_data(buf));
  buf2 = kbuf_init(ctx, 0);
  kbuf_strcpy(buf2, "1 2 3");
  kbuf_append_str(buf2," 4 5 6");
  kbuf_consume(buf2, 4);
  kbuf_asciiz(buf2);
  printf("[%s]\n", kbuf_data(buf2));
  buf = kbuf_init(ctx, 0);
  kbuf_sprintf(buf, "foobar %u [%s]", 0x242, "foo");
  kbuf_asciiz(buf);
  printf("fmt [%s]\n", kbuf_data(buf));
  printf("freeing\n");
  kbuf_free_ctx(ctx);
  dump_all_ctxs();
  ctx = kbuf_new_ctx();
  buf = kbuf_init(ctx, 0x666);
  kbuf_strcpy(buf, "foo\nbar\nblutti\nfnutti");
  buf2 = kbuf_init(ctx, 0);
  while ((i = kbuf_chr(buf, '\n')) != -1)
  {
    kbuf_split(buf, buf2, i);
    kbuf_asciiz(buf2);
    printf("split [%s]\n", kbuf_data(buf2));
  }
  kbuf_asciiz(buf);
  printf("rem [%s]\n", kbuf_data(buf));
  dump_all_ctxs();
  kbuf_free_ctx(ctx);
#endif
  kbuf_free_ctx(ctx);
  return 0;
}
#endif
