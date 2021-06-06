#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

extern u32 write(u32 fd, void * buffer, u32 len);
extern u32  read(u32 fd, void * buffer, u32 len);
extern void int2str(char *str, u32 num);
extern u32 str2int(char *buffer);
extern u32 reverse(char * buffer1, char *buffer2, u32 len);
extern u32 print(char *);
extern u32 gets(char *, u32 len);
extern u32 strncmp(char *, char *, u32);