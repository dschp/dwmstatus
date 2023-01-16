#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <tls.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define MAX_ACCOUNTS 10
#define CRLF "\r\n"
#define READ_BUFFER_SIZE 1024
#define NEEDLE_BUFFER_SIZE 100
#define UNSEENS_SIZE 128
#define RECONNECT_INTERVAL 30
#define INACTIVITY_TIME_LIMIT 200
#define IDLE_TIME_LIMIT 25 * 60

struct Account {
   char *name;
   char *user;
   char *password;
   char *server;
   char *port;
};

struct Client {
   struct Account *account;
   struct tls_config *config;
   struct addrinfo *addrinfo;
   struct tls *tls;
   int socket;

   enum Phase {Disconnected, Connected} phase;
   short events;
   int (*handler)(struct Client*, char *line);

   char *read_buffer;
   char *rb_cur_pos;
   size_t rb_size;
   char needle_buffer[NEEDLE_BUFFER_SIZE];
   size_t nb_size;
   size_t needle_length;

   size_t conn_cnt;
   time_t timer1;
   time_t timer2;
   size_t seq;
   size_t exists;
   int us_cnt;
   int *unseens;
   size_t us_size;
};

int setup_config(struct tls_config *cfg);
size_t load_accounts(struct Account as[]);
void client_init(struct Client*, struct tls_config*, struct Account*);
int client_connect(struct Client*);
int client_starttls(struct Client*);
void client_disconnect(struct Client*);
ssize_t client_read(struct Client*);
ssize_t client_write(struct Client*, const void *buf, size_t len, char *log);
int client_login(struct Client*, char*);
int client_login_sent(struct Client*, char*);
int client_select_sent(struct Client*, char*);
void client_search(struct Client*);
int client_search_sent(struct Client*, char*);
int client_idle_sent(struct Client*, char*);
void client_idle_check_time_limit(struct Client*, time_t);
void client_idle_done(struct Client*);
int client_idle_done_sent1(struct Client*, char*);
int client_idle_done_sent2(struct Client*, char*);
void client_logout(struct Client*);
int client_logout_sent(struct Client*, char*);

void add_unseens(struct Client*, int);
void remove_unseens(struct Client*, int);
void decrement_unseens(struct Client*, int);
void print_unseens(struct Client*);

void main_loop(const char *, struct tls_config*);

#define log_app(fmt,...) fprintf(stdout, fmt "\n", __VA_ARGS__);
#define log_app_(msg) fprintf(stdout, msg "\n");
#define err_app(fmt,...) fprintf(stderr, fmt "\n", __VA_ARGS__);
#define err_app_(msg) fprintf(stderr, msg "\n");

#define log_account(account,fmt,...) fprintf(stdout, "  [%s] " fmt "\n", account->name, __VA_ARGS__);
#define log_account_(account,msg) fprintf(stdout, "  [%s] " msg "\n", account->name);
#define err_account(account,fmt,...) fprintf(stderr, "  [%s] " fmt "\n", account->name, __VA_ARGS__);
#define err_account_(account,msg) fprintf(stderr, "  [%s] " msg "\n", account->name);

int main(int argc, char *argv[]) {
   if (argc < 2) {
      err_app_("Status file not specified.");
      exit(1);
   }

   if (tls_init() != 0) {
      err_app_("tls_init failed");
      exit(2);
   }

   struct tls_config *cfg = tls_config_new();
   if (cfg == NULL) {
      err_app_("tls_config_new failed");
      exit(3);
   }

   if (setup_config(cfg) == 0) {
      main_loop(argv[1], cfg);
   }

   tls_config_free(cfg);
   return 0;
}

void main_loop(const char *file, struct tls_config *cfg) {
   struct Account accounts[MAX_ACCOUNTS];
   const size_t num_accounts = load_accounts(accounts);

   struct Client clients[num_accounts];
   struct pollfd pfds[num_accounts];
   int last_cnts[num_accounts];

   for (int i = 0; i < num_accounts; i++) {
      client_init(&clients[i], cfg, &accounts[i]);
      last_cnts[i] = -1;
   }

   while (true) {
      time_t now = time(NULL);
      for (int i = 0; i < num_accounts; i++) {
         struct Client *c = &clients[i];
         struct Account *a = &accounts[i];
         struct pollfd *p = &pfds[i];

         time_t elapsed = now - c->timer1;
         switch (c->phase) {
            case Disconnected:
               if (elapsed > RECONNECT_INTERVAL) {
                  client_connect(c);
               } else if (now - c->timer2 > 10) {
                  log_account(a, "Reconnect Timer: %d sec", elapsed);
                  c->timer2 = now;
               }
               break;
            case Connected:
               // check inactivity
               if (elapsed > INACTIVITY_TIME_LIMIT) {
                  log_account(a, "Inactivity: %d sec", elapsed);
                  if (c->handler == client_idle_sent) {
                     client_idle_done(c);
                  } else if (c->handler != client_logout_sent) {
                     client_logout(c);
                  } else {
                     client_disconnect(c);
                  }
               }
               break;
         }

         p->fd = (c->events == 0 ? -1: c->socket);
         p->events = c->events | POLLHUP;
      }

      const int poll_rc = poll(pfds, num_accounts, 5000);
      if (poll_rc == 0) continue;

      struct tm *tp = localtime(&now);
      char ts[20];
      strftime(ts, sizeof(ts), "%F %T", tp);
      log_app("%s | poll() => %d", ts, poll_rc);

      for (int i = 0; i < num_accounts; i++) {
         struct Client *c = &clients[i];
         struct Account *a = &accounts[i];
         struct pollfd *p = &pfds[i];
         if (p->revents == 0) continue;

         char buf[200];
         log_account(a, "socket=%d, events=%d, conn_cnt=%d, seq=%d, exists=%d", c->socket, c->events, c->conn_cnt, c->seq, c->exists);
         log_account(a, "pfd: fd=%d, events=%d, revents=%d", p->fd, p->events ^ POLLHUP, p->revents);
         if (p->revents == 0) continue;

         if (p->revents & (POLLERR | POLLNVAL)) {
            err_account_(a, "POLLERR or POLLNVAL");
            exit(1);
            continue;
         }
         if (p->revents & POLLHUP) {
            err_account_(a, "POLLHUP");
            client_disconnect(c);
            continue;
         }

         int rc;
         switch (c->phase) {
            case Disconnected:
               break;
            case Connected:
               if ((p->revents & POLLIN) != 0) {
                  int (*hdlr)(struct Client*, char*) = c->handler;
                  if (hdlr == NULL) {
                     client_disconnect(c);
                     continue;
                  }
                  if (hdlr == client_idle_sent)
                     print_unseens(c);

                  rc = client_read(c);
                  if (rc == 0) {
                     client_disconnect(c);
                     continue;
                  } else if (rc < 0) {
                     continue;
                  }

                  char *p1, *p2;
                  p1 = c->read_buffer;
                  while ((p2 = strstr(p1, CRLF)) != NULL) {
                     *p2 = '\0';
                     log_account(a, "\"%s\"", p1);

                     hdlr(c, p1);

                     p1 = p2 + 2;
                     if (p1 > c->read_buffer + c->rb_size) break;
                  }

                  if (hdlr == client_idle_sent)
                     client_idle_check_time_limit(c, now);
               }
               if (c->handler == NULL && (p->revents & POLLOUT) != 0) {
                  client_starttls(c);
                  c->needle_length = snprintf(c->needle_buffer, c->nb_size, "* OK");
                  c->handler = client_login;
               }

               break;
         }
      }

      bool changed = false;
      char buf[200];
      char *p = buf;
      for (int i = 0; i < num_accounts; i++) {
         struct Client *c = &clients[i];
         struct Account *a = &accounts[i];

         if (c->us_cnt != last_cnts[i]) changed = true;
         last_cnts[i] = c->us_cnt;

         if (c->us_cnt > 0) {
            p+= snprintf(p, sizeof(buf) - (p - buf), "(%s: %d) ", a->name, c->us_cnt);
         }
      }
      if (p > buf) {
         p+= snprintf(p, sizeof(buf) - (p - buf), "| ");
      } else {
         *p = '\0';
      }

      if (changed) {
         FILE *fd = fopen(file, "w");
         if (fd == NULL) {
            err_app("File could not be opened: %s", file);
            break;
         }
         if (p != buf) fprintf(fd, buf);
         fclose(fd);
      }
   }

   for (int i = 0; i < num_accounts; i++) {
      struct Client *c = &clients[i];
      client_disconnect(c);

      free(accounts[i].name);
      if (clients[i].read_buffer != NULL)
         free(clients[i].read_buffer);
      if (clients[i].unseens != NULL)
         free(clients[i].unseens);
   }
}

int setup_config(struct tls_config *cfg) {
   if (tls_config_set_protocols(cfg, TLS_PROTOCOLS_DEFAULT) != 0) {
      err_app_("tls_config_set_protocols failed");
      return 1;
   }
   if (tls_config_set_ca_file(cfg, "/opt/libressl/etc/ssl/cert.pem") != 0) {\
      err_app_("tls_config_set_ca_file failed");
      return 2;
   }
   if (tls_config_set_ciphers(cfg, "secure") != 0) {
      err_app_("tls_config_set_ciphers failed");
      return 3;
   }

   return 0;
}

size_t load_accounts(struct Account as[]) {
   size_t num_accounts = 0;

   for (int i = 0; i < MAX_ACCOUNTS; i++) {
      char *input = NULL;
      size_t length = 0;
      ssize_t bytes_read = 0;

      if ((bytes_read = getline(&input, &length, stdin)) == EOF) break;
      input[strlen(input) -1] = '\0';

      struct Account *a = &as[i];

      if ((a->name = strtok(input, " ")) == NULL
            || (a->user = strtok(NULL, " ")) == NULL
            || (a->password = strtok(NULL, " ")) == NULL
            || (a->server = strtok(NULL, " ")) == NULL
            || (a->port = strtok(NULL, " ")) == NULL) {

         free(input);
         continue;
      }

      printf("[%s] %s ", a->name, a->user);
      for (size_t i2 = 0; a->password[i2] != '\0'; i2++) {
         putchar((i2 % 8 == 0) ? a->password[i2] : '*');
      }
      printf(" %s:%s\n", a->server, a->port);
      num_accounts++;
   }

   return num_accounts;
}

void client_init(struct Client *c, struct tls_config *cfg, struct Account *a) {
   c->account = a;
   c->config = cfg;
   c->addrinfo = NULL;
   c->tls = NULL;
   c->socket = -1;

   c->phase = Disconnected;
   c->events = 0;

   c->read_buffer = NULL;
   c->rb_cur_pos = NULL;
   c->rb_size = 0;
   c->nb_size = sizeof(c->needle_buffer);

   c->us_cnt = 0;
   c->unseens = NULL;
   c->us_size = 0;

   c->conn_cnt = 0;
   c->timer1 = 0;
   c->timer2 = 0;
}

int client_connect(struct Client *c) {
   struct Account *a = c->account;

   if (c->phase != Disconnected) {
      err_account_(a, "client_connect: is not Disconnected");
      return 1;
   }

   struct addrinfo hints;
   memset(&hints, '\0', sizeof(hints));

   int rc = getaddrinfo(a->server, a->port, &hints, &c->addrinfo);
   if (rc != 0) {
      const char *err = gai_strerror(rc);
      err_account(a, "getaddrinfo: %s\n", err);
      return 2;
   }

   if (c->tls == NULL) {
      if ((c->tls = tls_client()) == NULL) {
         err_account_(a, "tls_client failed");
         return 3;
      }
   }

   log_account(a, "Connecting -> %s:%s", a->server, a->port);

   c->socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
   if (c->socket < 0) {
      err_account_(a, "socket failed");
      return 4;
   } else {
      log_account(a, "socket: success (%d)", c->socket);

      rc = connect(c->socket, c->addrinfo->ai_addr, c->addrinfo->ai_addrlen);
      if (rc < 0) {
         if (errno == EINPROGRESS) {
            log_account_(a, "connect: In Progress");
         } else {
            err_account(a, "connect: error (%d, %d)\n", rc, errno);

            client_disconnect(c);
            return 5;
         }
      } else {
         log_account_(a, "connect: success");
      }
   }

   rc = tls_configure(c->tls, c->config);
   if (rc != 0) {
      err_account_(a, "tls_configure failed");
      return 6;
   }
   log_account_(a, "tls_configure: success");

   if (tls_connect_socket(c->tls, c->socket, c->account->server) != 0) {
      err_account_(a, "tls_connect_socket failed");
      return 7;
   }
   log_account_(a, "tls_connect_socket: success");

   if (c->read_buffer == NULL) {
      if ((c->read_buffer = malloc(READ_BUFFER_SIZE)) == NULL) {
         err_account_(a, "malloc failed");
         return -1;
      }
      c->rb_size = READ_BUFFER_SIZE;
      c->rb_cur_pos = c->read_buffer;
   }

   if (c->unseens == NULL) {
      if ((c->unseens = malloc(sizeof(int) * UNSEENS_SIZE)) == NULL) {
         err_account_(a, "unseens: malloc failed");
         return -1;
      }
      c->us_size = UNSEENS_SIZE;
   }

   c->phase = Connected;
   c->events = POLLOUT;
   c->handler = NULL;

   c->seq = 0;
   c->exists = 0;
   c->us_cnt = 0;

   c->conn_cnt++;
   c->timer1 = time(NULL);
   c->timer2 = 0;

   for (int i = 0; i < c->us_size; i++) c->unseens[i] = -1;

   snprintf(c->needle_buffer, c->nb_size, "* OK");
   return 0;
}

void client_disconnect(struct Client *c) {
   struct Account *a = c->account;
   if (c->phase == Disconnected) {
      err_account_(a, "client_connect: is Disconnected");
      return;
   }

   log_account(a, "Disconnecting -> %s:%s", a->server, a->port);

   if (c->tls != NULL) {
      if(tls_close(c->tls) != 0) {
         log_account_(a, "tls_close failed");
      }
      tls_reset(c->tls);
   }
   if (c->socket > 0) {
      int rc;
      rc = shutdown(c->socket, SHUT_RDWR);
      log_account(a, "shutdown: %d", rc);

      rc = close(c->socket);
      log_account(a, "close: %d", rc);

      c->socket = 0;
   }
   freeaddrinfo(c->addrinfo);

   c->phase = Disconnected;
   c->events = 0;
   c->timer1 = time(NULL);
   c->timer2 = 0;
}

ssize_t client_read(struct Client *c) {
   struct Account *a = c->account;

   size_t len = c->rb_size - (c->rb_cur_pos - c->read_buffer);
   while (true) {
      int rc = tls_read(c->tls, c->rb_cur_pos, len);
      log_account(a, "<<< tls_read: %d", rc);

      if (rc <= 0) {
         switch (rc) {
            case TLS_WANT_POLLIN:
               err_account_(a, "tls_read: TLS_WANT_POLLIN");
               c->events = POLLIN;
               break;
            case TLS_WANT_POLLOUT:
               err_account_(a, "tls_read: TLS_WANT_POLLOUT");
               c->events = POLLOUT;
               break;
         }
         return rc;
      }

      c->rb_cur_pos += rc;
      if (strncmp(CRLF, c->rb_cur_pos - 2, 2) == 0) break;

      if (rc < len) {
         len -= rc;
      } else {
         size_t new_size = c->rb_size * 2;
         void *new_ptr = realloc(c->read_buffer, new_size);
         if (new_ptr == NULL) {
            err_account(a, "read_buffer realloc failed: {%p} %d -> %d", c->read_buffer, c->rb_size, new_size);
            exit(1);
         }

         c->rb_cur_pos = new_ptr + (c->rb_cur_pos - c->read_buffer);
         len = c->rb_size;
         c->read_buffer = new_ptr;
         c->rb_size = new_size;
      }
   }

   size_t bytes = c->rb_cur_pos - c->read_buffer;
   if (bytes > 0) {
      c->timer1 = time(NULL);
      *c->rb_cur_pos = '\0';
      c->rb_cur_pos = c->read_buffer;
   }
   return bytes;
}

bool _client_write(struct Client *c, const void *buf, size_t len) {
   while (len > 0) {
      ssize_t rc = tls_write(c->tls, buf, len);
      if (rc == TLS_WANT_POLLIN || rc == TLS_WANT_POLLOUT)
         continue;
      if (rc == -1) {
         return false;
      }

      buf += rc;
      len -= rc;
   }
   return true;
}

ssize_t client_write(struct Client *c, const void *buf, size_t len, char *log) {
   log_account(c->account, ">>> tls_write: %d", len);
   log_account(c->account, "\"%s\"", log);
   
   if (! _client_write(c, buf, len)) return -1;
   if (! _client_write(c, CRLF, 2)) return -1;

   return len;
}

int client_starttls(struct Client *c) {
   struct Account *a = c->account;

   if (c->phase != Connected) {
      err_account_(a, "client_connect: is not Connected");
      return 1;
   }

   int rc = tls_handshake(c->tls);
   switch (rc) {
      case 0:
         log_account_(a, "tls_handshake: success");
         c->events = POLLIN;
         break;
      case TLS_WANT_POLLIN:
         err_account_(a, "tls_handshake: TLS_WANT_POLLIN");
         c->events = POLLIN;
         break;
      case TLS_WANT_POLLOUT:
         err_account_(a, "tls_handshake: TLS_WANT_POLLOUT");
         c->events = POLLOUT;
         break;
      default:
         err_account(a, "tls_handshake failed: %d", rc);
         return 2;
   }

   return 0;
}

int client_login(struct Client *c, char* line) {
   struct Account *a = c->account;
   char buf[200], log[200];

   log_account(a, "'%s'", c->needle_buffer);
   if (strncmp(line, c->needle_buffer, c->needle_length) != 0) {
      return 1;
   }

   c->seq++;
   int len = snprintf(buf, sizeof(buf), "A%d LOGIN %s %s", c->seq, a->user, a->password);
   snprintf(log, sizeof(log), "A%d LOGIN %s ********", c->seq, a->user);
   client_write(c, buf, len, log);

   c->needle_length = snprintf(c->needle_buffer, c->nb_size, "A%d ", c->seq);
   c->handler = client_login_sent;
   return 0;
}

int client_login_sent(struct Client *c, char *line) {
   struct Account *a = c->account;
   char buf[100];

   log_account(a, "'%s'", c->needle_buffer);
   if (strncmp(line, c->needle_buffer, c->needle_length) != 0) {
      return 1;
   }

   c->seq++;
   int len = snprintf(buf, sizeof(buf), "A%d SELECT INBOX", c->seq);
   client_write(c, buf, len, buf);

   c->needle_length = snprintf(c->needle_buffer, c->nb_size, "A%d OK ", c->seq);
   c->handler = client_select_sent;
   return 0;
}

int client_select_sent(struct Client *c, char *line) {
   struct Account *a = c->account;
   char *p;

   char exists[] = " EXISTS";
   if ((p = strstr(line, exists)) != NULL) {
      *p = '\0';
      int num = strtol(&line[2], NULL, 10);
      if (errno == ERANGE) {
         err_account_(a, "strtol: ERANGE");
         c->exists = 0;
         return 1;
      } else {
         log_account(a, "Parsed Exists: %d", num);
         c->exists = num;
      }
      return 0;
   }

   log_account(a, "'%s'", c->needle_buffer);
   if (strncmp(line, c->needle_buffer, c->needle_length) != 0) {
      return 1;
   }

   client_search(c);
   return 0;
}

void client_search(struct Client *c) {
   char buf[100];

   for (int i = 0; i < c->us_cnt; i++) c->unseens[i] = -1;
   c->us_cnt = 0;

   c->seq++;
   int len = snprintf(buf, sizeof(buf), "A%d SEARCH (UNSEEN)", c->seq);
   client_write(c, buf, len, buf);

   c->needle_length = snprintf(c->needle_buffer, c->nb_size, "A%d OK ", c->seq);
   c->handler = client_search_sent;
}

int client_search_sent(struct Client *c, char *line) {
   struct Account *a = c->account;
   char buf[100], *p;

   char search[] = "* SEARCH";
   if ((p = strstr(line, search)) != NULL) {
      p += sizeof(search) -1;
      if (*p == '\0') {
         return 1;
      }
      p++;
      log_account(a, "Search: '%s'", p);

      p = strtok(p, " ");
      while (p != NULL) {
         log_account(a, "token: %s", p);

         int num = strtol(p, NULL, 10);
         if (errno == ERANGE) {
            err_account(a, "token error: %s", p);
         } else {
            add_unseens(c, num);
         }

         p = strtok(NULL, " ");
      }
      print_unseens(c);

      return 0;
   }

   log_account(a, "'%s'", c->needle_buffer);
   if (strncmp(line, c->needle_buffer, c->needle_length) != 0) {
      return 1;
   }

   c->seq++;
   int len = snprintf(buf, sizeof(buf), "A%d IDLE", c->seq);
   client_write(c, buf, len, buf);

   c->needle_length = snprintf(c->needle_buffer, c->nb_size, "A%d OK ", c->seq);
   c->handler = client_idle_sent;
   c->timer2 = time(NULL);
   return 0;
}

int client_idle_sent(struct Client *c, char *line) {
   struct Account *a = c->account;

   if (strncmp(line, c->needle_buffer, c->needle_length) == 0) {
      client_search(c);
      return 0;
   }

   if (strncmp(line, "* ", 2) != 0) {
      return 0;
   }

   char *tkn1 = line + 2;
   char *p= strstr(tkn1, " ");
   if (p == NULL) {
      err_account_(a, "Invalid IDLE response");
      return 1;
   }
   *p = '\0';
   if (strcmp(tkn1, "OK") == 0) {
      return 0;
   } else if (strcmp(tkn1, "BYE") == 0) {
      client_idle_done(c);
      c->handler = client_idle_done_sent2;
      return 0;
   }

   char *tkn2 = p + 1;
   p = strstr(tkn2, " ");
   char *rest;
   if (p == NULL) {
      log_account(a, "Tokens: %s|%s", tkn1, tkn2);
      rest = tkn2;
   } else {
      *p = '\0';
      rest = p + 1;
      log_account(a, "Tokens: %s|%s|%s", tkn1, tkn2, rest);
   }

   const int num = strtol(tkn1, NULL, 10);

   if (strcmp(tkn2, "FETCH") == 0) {
      if ((strstr(rest, "\\Seen")) == NULL) {
         log_account(a, "Unseen Add: %d", num);
         add_unseens(c, num);
         print_unseens(c);
      } else {
         log_account(a, "Unseen Remove: %d", num);
         remove_unseens(c, num);
         print_unseens(c);
      }
   } else if (strcmp(tkn2, "EXPUNGE") == 0) {
      log_account(a, "Unseen Remove: %d", num);
      remove_unseens(c, num);
      print_unseens(c);

      c->exists--;
      log_account(a, "Exists: %d", c->exists);

      log_account_(a, "Unseen Decrement");
      decrement_unseens(c, num);
      print_unseens(c);
   } else if (strcmp(tkn2, "EXISTS") == 0) {
      c->exists = num;
      log_account(a, "Exists: %d", c->exists);

      client_idle_done(c);
      c->handler = client_idle_done_sent1;
   }

   return 0;
}

void client_idle_check_time_limit(struct Client *c, time_t now) {
   struct Account *a = c->account;
   time_t elapsed = now - c->timer2;
   log_account(a, "IDLE for %d/%d sec", elapsed, IDLE_TIME_LIMIT);
   if (elapsed > IDLE_TIME_LIMIT) {
      client_idle_done(c);
      c->handler = client_idle_done_sent1;
   }
}

void client_idle_done(struct Client *c) {
   char done[] = "DONE";
   client_write(c, done, 4, done);
}

int client_idle_done_sent1(struct Client *c, char *line) {
   if (strncmp(line, c->needle_buffer, c->needle_length) != 0) {
      return 0;
   }

   client_search(c);
   return 0;
}

int client_idle_done_sent2(struct Client *c, char *line) {
   if (strncmp(line, c->needle_buffer, c->needle_length) != 0) {
      return 0;
   }

   client_logout(c);
   return 0;
}

void client_logout(struct Client *c) {
   struct Account *a = c->account;
   char buf[100];

   c->seq++;
   int len = snprintf(buf, sizeof(buf), "A%d LOGOUT", c->seq);
   client_write(c, buf, len, buf);

   snprintf(c->needle_buffer, c->nb_size, "A%d OK", c->seq);
   c->handler = client_logout_sent;
}

int client_logout_sent(struct Client *c, char *line) {
   if (strncmp(line, c->needle_buffer, c->needle_length) != 0) {
      return 0;
   }

   client_disconnect(c);
   return 0;
}

void add_unseens(struct Client* c, int num) {
   int i = 0;
   for (; i < c->us_cnt; i++) {
      if (c->unseens[i] == num) {
         return;
      }
   }
   if (i > c->us_size) {
      size_t new_size = c->us_size * 2;
      int *new_ptr = realloc(c->unseens, sizeof(int) * new_size);
      if (new_ptr == NULL) {
         err_account(c->account, "unseens realloc failed: {%p} %d -> %d", c->unseens, c->us_size, new_size);
         exit(1);
      }

      c->unseens = new_ptr;
      c->us_size = new_size;
      for (int j = i; j < c->us_size; j++) c->unseens[j] = -1;
   }

   c->us_cnt++;
   c->unseens[i] = num;
}

void remove_unseens(struct Client* c, int num) {
   for (int i = 0; i < c->us_cnt; i++) {
      if (c->unseens[i] == num) {
         c->us_cnt--;
         if (i == c->us_cnt) {
            c->unseens[i] = -1;
         } else {
            c->unseens[i] = c->unseens[c->us_cnt];
         }
         break;
      }
   }
}

void decrement_unseens(struct Client* c, int num) {
   for (int i = 0; i < c->us_cnt; i++) {
      if (c->unseens[i] > num) {
         c->unseens[i] -= 1;
      }
   }
}

void print_unseens(struct Client *c) {
   char buf[300];
   char *p = buf;
   p += snprintf(buf, sizeof(buf), "Unseen: %d (", c->us_cnt);
   for (int i = 0; i < c->us_cnt; i++) {
      p+= snprintf(p, sizeof(buf) - (p - buf), "%d,", c->unseens[i]);
   }
   p += snprintf(p, sizeof(buf), ")");

   log_account(c->account, "%s", buf);
}
