#ifndef _STRMODE_H_
#define _STRMODE_H_

#include <sys/stat.h>

char *jev_strmode(mode_t mode, char *p);

#if defined(__ANDROID__) && __ANDROID_API__ < 23

#include <dirent.h>

void seekdir(DIR* d, long offset);

long telldir(DIR* d);

#endif

#endif // _STRMODE_H_
