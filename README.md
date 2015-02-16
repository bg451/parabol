## Parabol

Torrent peer tracking system

An attempt at a peer tracking system for torrents. I lost a few of the files after my old laptop's harddrive failed, so I have no clue if this will still compile and work properly. In retrospect, I probably shouldve used version control back then.

How to compile
 - Edit asio/asio.h and select what async I/O interface you wanna use.
 - Edit Makefile
   - If you are on Linux, USE_LINUX_SENDFILE should be defined
   - If you are on Linux, using epoll (kernel >=2.6), and have a libc which
     doesn't support them (you'll get 'epoll_* is not implemented and
     will always fail' warning on linking), uncomment the KEPOLL* lines.
 - Put final touches to config.h.
   DEBUG is enabled by default

Then make
The other config settings are in parabol.cfg

Brandon Gonzalez <bg451@hotmail.com>
