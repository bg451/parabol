//#define GRAIN_SIZE		0x1000		/* must be power of 2 */
//#define KBUF_CTX_HASH_SIZE	0x400000	/* must be power of 2 */
#define GRAIN_SIZE 0x100
#define KBUF_CTX_HASH_SIZE 0x40000
	
#define Ksize_t	size_t
#define Kssize_t	ssize_t

#define Kbuf_PANIC(f...) kbuf_panic(__FILE__, __LINE__, NULL, 0, ##f)
#define Kbuf_PANIC_FROM(f...) kbuf_panic(__FILE__, __LINE__, from_file, from_line, ##f)
#define Kbuf_ASSERT(cond) if (!(cond)) kbuf_panic(__FILE__, __LINE__, NULL, 0, "Assertion (" __STRING(cond) ") failed")
#ifdef KBUF_DEBUG
#define Kbuf_dASSERT(cond) Kbuf_ASSERT(cond)
#else
#define Kbuf_dASSERT(cond)
#endif

#define Kfree(ptr) if ((ptr) != NULL) { free(ptr); (ptr) = NULL; }

typedef unsigned int kbuf_ctxh;

#define Kbuf_INVALID_CTX ((kbuf_ctxh)-1)

typedef struct kbuf_s kbuf;
typedef struct kbuf_ctx_s kbuf_ctx;

struct kbuf_s
{
  unsigned int in_use;
  kbuf *prev;
  kbuf *next;
  unsigned int idx;
  Ksize_t size;
  unsigned char *head;
};

struct kbuf_ctx_s
{
  kbuf_ctxh hnd;
  kbuf *head;
  kbuf_ctx *prev;
  kbuf_ctx *next; 
};

typedef struct kbuf_table_s kbuf_table;
typedef struct kbuf_table_entry_s kbuf_table_entry;

struct kbuf_table_s
{
  kbuf_ctxh ctxh;
  unsigned int type;
  kbuf_table_entry *head;
  kbuf_table_entry *tail;
};

struct kbuf_table_entry_s
{
  kbuf *key;
  kbuf *data;
  kbuf_table_entry *prev;
  kbuf_table_entry *next;
};

enum { KBUF_TABLE_NOCASE, KBUF_TABLE_CASE, KBUF_TABLE_BIN };

void kbuf_panic(unsigned char *, unsigned int, unsigned char *, unsigned int, unsigned char *, ...);
kbuf_ctxh kbuf_new_ctx(void);
void kbuf_free(kbuf_ctxh, kbuf *);
void _kbuf_free_ctx(kbuf_ctxh, unsigned char *, unsigned int);
void kbuf_consume(kbuf *, Ksize_t);
unsigned char kbuf_eat_byte(kbuf *);
int kbuf_chr(kbuf *, unsigned char);
void kbuf_asciiz(kbuf *);

kbuf *kbuf_init(kbuf_ctxh, Ksize_t);
void kbuf_set_size(kbuf *, Ksize_t);
void kbuf_set_data(kbuf *, unsigned char *, Ksize_t);
void kbuf_append_data(kbuf *, unsigned char *, Ksize_t);
void kbuf_append_byte(kbuf *, unsigned char);
void kbuf_vsprintf(kbuf *, unsigned char *, va_list);
void kbuf_sprintf(kbuf *, unsigned char *, ...);
void kbuf_appendf(kbuf *, unsigned char *, ...);

kbuf_table *kbuf_table_init(kbuf_ctxh, unsigned int);
kbuf_table_entry *kbuf_table_entry_add(kbuf_ctxh, kbuf_table *, unsigned char *, kbuf *);
kbuf_table_entry *kbuf_table_entry_add_buf(kbuf_ctxh, kbuf_table *, kbuf *, kbuf *);
kbuf_table_entry *kbuf_table_entry_add_str(kbuf_ctxh, kbuf_table *, unsigned char *, unsigned char *);
kbuf_table_entry *kbuf_table_entry_find(kbuf_table *, unsigned char *);
kbuf *kbuf_table_entry_get(kbuf_table *, unsigned char *);
unsigned char *kbuf_table_entry_get_str(kbuf_table *, unsigned char *);

void kbuf_urlencode_data(unsigned char *, Ksize_t, kbuf *);
void kbuf_base64encode_data(unsigned char *, Ksize_t, kbuf *);

#define kbuf_free_ctx(ctx) _kbuf_free_ctx((ctx), __FILE__, __LINE__)
#define kbuf_idx(buf) ((buf)->idx)
#define kbuf_size(buf) ((buf)->size)
#define kbuf_data(buf) ((buf)->head)
#define kbuf_empty(buf) (kbuf_idx(buf) == 0)

#define kbuf_strcpy(buf, str) kbuf_set_data((buf), (str), strlen(str))
#define kbuf_append_str(buf, str) kbuf_append_data((buf), (str), strlen(str))
#define kbuf_clone(buf, src) kbuf_set_data((buf), kbuf_data(src), kbuf_idx(src))
#define kbuf_append_buf(buf, src) kbuf_append_data((buf), kbuf_data(src), kbuf_idx(src))

#define kbuf_urlencode(buf, out) kbuf_urlencode(kbuf_data(buf), kbuf_idx(buf), (out))

#define kbuf_split(buf, dest, idx)\
	{\
	  kbuf_set_data((dest), kbuf_data((buf)), (idx));\
	  kbuf_consume((buf), (idx) + 1);\
	}

#define kbuf_set_byte(buf, idx, byte)\
	{\
	  Kbuf_ASSERT((unsigned int)(idx) < kbuf_idx(buf) && (unsigned int)(idx) < kbuf_size(buf));\
	  *(kbuf_data(buf) + (idx)) = (byte);\
	}
#define kbuf_consume_end(buf, len)\
	{\
	  Kbuf_ASSERT((unsigned int)(len) <= kbuf_idx(buf));\
	  kbuf_idx(buf) -= (len);\
	}
#define kbuf_set_idx(buf, idx)\
	{\
	  Kbuf_ASSERT((unsigned int)(idx) <= kbuf_size(buf));\
	  kbuf_idx(buf) = (idx);\
	}
#define kbuf_get_byte(buf, idx, byte)\
	{\
	  Kbuf_ASSERT((unsigned int)(idx) < kbuf_idx(buf));\
	  (byte) = *(kbuf_data(buf) + (idx));\
	}
