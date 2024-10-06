#include <X11/Xlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define MAX_FILE 10
#define SEPARATOR " / "
#define SEP_LEN sizeof(SEPARATOR) - 1

int filter(const struct dirent *entry) {
  return entry->d_type == DT_REG;
}

void main(int argc, char *argv[]) {
  if (argc > 2) {
    fprintf(stderr, "Too many arguments\n");
    exit(1);
  }

  if (argc == 2) {
    if (chdir(argv[1]) == -1) {
      fprintf(stderr, "chdir failed: [%s] (%d)\n", argv[1], errno);
      exit(EXIT_FAILURE);
    }
  }

  char *env_dsp = getenv("DISPLAY");
  if (env_dsp == NULL) {
    fprintf(stderr, "Envvar DISPLAY not defined\n");
    exit(EXIT_FAILURE);
  }

  Display* dsp = XOpenDisplay(env_dsp);
  if (dsp == NULL) {
    fprintf(stderr, "XOpenDisplay error\n");
    exit(EXIT_FAILURE);
  }

  Window win = DefaultRootWindow(dsp);

  while (true) {
    time_t now = time(NULL);
    struct tm *tm;
    char dtbuf[100], statbuf[300];
    char *p = dtbuf;

    setenv("TZ", ":EST", 1);
    tm = localtime(&now);
    p += strftime(p, sizeof(dtbuf) - (p - dtbuf), "EST:\x03%R\x01 ", tm);

    tm = gmtime(&now);
    p += strftime(p, sizeof(dtbuf) - (p - dtbuf), "UTC:\x04%R\x01 ", tm);

    setenv("TZ", ":Asia/Tokyo", 1);
    tm = localtime(&now);
    p += strftime(p, sizeof(dtbuf) - (p - dtbuf), "JST:\x05%R\x01 ", tm);

    setenv("TZ", ":Asia/Bangkok", 1);
    tm = localtime(&now);
    p += strftime(p, sizeof(dtbuf) - (p - dtbuf), "%F (%a) \x06%T\x01", tm);

    p += snprintf(p, sizeof(dtbuf) - (p - dtbuf), " [%d]", tm->tm_year + 1900 + 543);

    if (argc == 1) {
      p = dtbuf;
    } else {
      struct dirent **namelist;
      const int n = scandir(".", &namelist, filter, alphasort);
      if (n == -1) {
	perror("scandir");
	break;
      }

      const size_t dt_len = p - dtbuf + 1;
      const char *statbuf_cap = statbuf + sizeof(statbuf) - dt_len;
      p = statbuf;
      for (int i = 0; i < n; i++) {
	if (i < MAX_FILE && p < statbuf_cap) {
	  const size_t remaining = statbuf_cap - p;

	  FILE *fp = fopen(namelist[i]->d_name, "a+");
	  if (fp == NULL) {
	    fprintf(stderr, "fopen error: %s\n", argv[i]);
	  } else {
	    char readbuf[remaining];
	    int r = fread(readbuf, 1, sizeof(readbuf), fp);
	    fclose(fp);

	    if (r < 1) continue;

	    const char *rend = readbuf + r;
	    char *rp = readbuf;
	    while (rp < rend) {
	      switch (*rp) {
	      case '\n':
	      case '\r':
		if (statbuf_cap - p < SEP_LEN) {
		  rp = readbuf + remaining;
		  break;
		}

		memcpy(p, SEPARATOR, SEP_LEN);
		p += SEP_LEN;
		break;
	      default:
		*p = *rp;
		p++;
	      }
	      rp++;
	    }
	  }
	}

	free(namelist[i]);
      }
      free(namelist);

      strcpy(p, dtbuf);
      p = statbuf;
    }

    XStoreName(dsp, win, p);
    XFlush(dsp);

    sleep(1);
  }

  XCloseDisplay(dsp);
  exit(EXIT_FAILURE);
}
