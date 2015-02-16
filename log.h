enum { LOG_NONE, LOG_ERROR, LOG_INFO, LOG_REQUEST, LOG_CONNECTION, LOG_DEBUG, LOG_ALL };

void log_init(void);
void klogf(unsigned int, unsigned char *, ...);
void kperror(unsigned char *);
unsigned char *get_date_str(time_t);
unsigned char *get_now_date_str(void);
