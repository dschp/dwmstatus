#include <X11/Xlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void main(int argc, char *argv[]) {
   for (int i = 0; i < argc; i++) {
      printf("[%d] %s\n", i, argv[i]);
   }

   Display* dsp = XOpenDisplay(":0");
   if (dsp == NULL) {
      fprintf(stderr, "XOpenDisplay error\n");
      exit(1);
   }
   
   Window win = DefaultRootWindow(dsp);

   while (true) {
      time_t now = time(NULL);
      struct tm *tm;
      char buf[256];
      size_t idx = 0;

      for (int i = 1; i < argc; i++) {
         FILE *fp = fopen(argv[i], "a+");
         if (fp == NULL) {
            fprintf(stderr, "fopen error: %s\n", argv[i]);
         } else {
            idx += fread(&buf[idx], 1, sizeof(buf) - idx, fp);
            fclose(fp);
         }
      }

      setenv("TZ", ":EST", 1);
      tm = localtime(&now);
      idx += strftime(&buf[idx], sizeof(buf) - idx, "EST:\x03%R\x01 ", tm);

      tm = gmtime(&now);
      idx += strftime(&buf[idx], sizeof(buf) - idx, "GMT:\x04%R\x01 ", tm);

      setenv("TZ", ":Asia/Tokyo", 1);
      tm = localtime(&now);
      idx += strftime(&buf[idx], sizeof(buf) - idx, "EST:\x05%R\x01 ", tm);

      setenv("TZ", ":Asia/Bangkok", 1);
      tm = localtime(&now);
      idx += strftime(&buf[idx], sizeof(buf) - idx, "%F (%a) \x06%T\x01", tm);

      snprintf(&buf[idx], sizeof(buf) - idx, " [%d]", tm->tm_year + 1900 + 543);

      XStoreName(dsp, win, buf);
      XFlush(dsp);

      sleep(1);
   }
}
