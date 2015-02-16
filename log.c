#include "parabol.h"

static kbuf_ctxh log_ctx;
static kbuf *log_buf, *date_buf;
static FILE *log_file;
static unsigned int log_level_val;

unsigned int log_initialized = 0;

extern parabol_config cfg;

void log_init(void)
{
  log_ctx = kbuf_new_ctx();
  log_buf = kbuf_init(log_ctx, 0);
  date_buf = kbuf_init(log_ctx, 32);
  log_level_val = LOG_NONE;
  if (cfg.log == 1)
  {
    switch (cfg.log_level[0])
    {
      case 'e': case 'E': log_level_val = LOG_ERROR; break;
      case 'i': case 'I': log_level_val = LOG_INFO; break;
      case 'r': case 'R': log_level_val = LOG_REQUEST; break;
      case 'c': case 'C': log_level_val = LOG_CONNECTION; break;
      case 'd': case 'D': log_level_val = LOG_DEBUG; break;
      case 'a': case 'A': log_level_val = LOG_ALL; break;
      default:
        fprintf(stderr, "Invalid log level '%s'.\n", cfg.log_level);
        exit(1);
        break;
    }
    if (cfg.log_file != NULL)
    {
      if ((log_file = fopen(cfg.log_file, "a+")) == NULL) { fprintf(stderr, "Couldn't open log file (%s): %s\n", cfg.log_file, strerror(errno)); exit(1); }
    } else
    {
      log_file = stdout;
    }
  }
  log_initialized = 1;
}
unsigned char *get_date_str(time_t t)
{
  kbuf_strcpy(date_buf, ctime(&t));
  if (kbuf_idx(date_buf) > 0) kbuf_consume_end(date_buf, 1);
  kbuf_asciiz(date_buf);
  return kbuf_data(date_buf);
}
unsigned char *get_now_date_str(void)
{
  return get_date_str(time(NULL));
}
void klogf(unsigned int level, unsigned char *fmt, ...)
{
  va_list va;
  unsigned int i, c;
    
  if (cfg.log == 0) return;
  if (level > log_level_val) return;
  va_start(va, fmt);
  if (log_initialized == 0)
  {
    vprintf(fmt, va);
    printf("\n");
    va_end(va);
    return;
  } 
  kbuf_vsprintf(log_buf, fmt, va);
  va_end(va);
  for (i = 0; i < kbuf_idx(log_buf); i ++)
  {
    kbuf_get_byte(log_buf, i, c);
    if (c < 0x20 || c > 0x7f) kbuf_set_byte(log_buf, i, '.');
  }
  kbuf_append_byte(log_buf, '\n');
  kbuf_asciiz(log_buf);
  fprintf(log_file, "Log: %s %s", get_now_date_str(), kbuf_data(log_buf));
  fflush(log_file);
  if (log_file != stdout && level == LOG_ERROR) fprintf(stderr, "Log: %s %s\n", get_now_date_str(), kbuf_data(log_buf));
  if (kbuf_size(log_buf) > BUF_SIZE) kbuf_set_size(log_buf, BUF_SIZE);
}
void kperror(unsigned char *msg)
{
  if (cfg.log == 0) return;
  if (msg == NULL || msg[0] == 0) msg = "(none)";
  klogf(LOG_ERROR, "Error: %s %s", msg, strerror(errno));
}
