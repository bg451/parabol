int Kepoll_create(int);
int Kepoll_ctl(int, int, int, struct epoll_event *);
int Kepoll_wait(int, struct epoll_event *, int, int);