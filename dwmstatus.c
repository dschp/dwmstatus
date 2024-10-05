#include <X11/Xlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

int filter(const struct dirent *entry) {
  return entry->d_type == DT_REG;
}

#define MAX_FILE 10

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
    char buf[256];
    size_t idx = 0;

    if (argc == 2) {
      struct dirent **namelist;

      int n = scandir(".", &namelist, filter, alphasort);
      if (n == -1) {
	perror("scandir");
	break;
      }

      for (int i = 0; i < n; i++) {
	if (i < MAX_FILE) {
	  FILE *fp = fopen(namelist[i]->d_name, "a+");
	  if (fp == NULL) {
	    fprintf(stderr, "fopen error: %s\n", argv[i]);
	  } else {
	    idx += fread(&buf[idx], 1, sizeof(buf) - idx, fp);
	    fclose(fp);
	  }
	}

	free(namelist[i]);
      }
      free(namelist);
    }

    for (int i = 0; i < idx; i++) {
      if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
    }

    setenv("TZ", ":EST", 1);
    tm = localtime(&now);
    idx += strftime(&buf[idx], sizeof(buf) - idx, "EST:\x03%R\x01 ", tm);

    tm = gmtime(&now);
    idx += strftime(&buf[idx], sizeof(buf) - idx, "UTC:\x04%R\x01 ", tm);

    setenv("TZ", ":Asia/Tokyo", 1);
    tm = localtime(&now);
    idx += strftime(&buf[idx], sizeof(buf) - idx, "JST:\x05%R\x01 ", tm);

    setenv("TZ", ":Asia/Bangkok", 1);
    tm = localtime(&now);
    idx += strftime(&buf[idx], sizeof(buf) - idx, "%F (%a) \x06%T\x01", tm);

    snprintf(&buf[idx], sizeof(buf) - idx, " [%d]", tm->tm_year + 1900 + 543);

    XStoreName(dsp, win, buf);
    XFlush(dsp);

    sleep(1);
  }

  XCloseDisplay(dsp);
  exit(EXIT_FAILURE);
}
