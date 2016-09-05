#if !defined(__TERMINAL_H__)
#define __TERMINAL_H__

#ifdef __cplusplus
extern "C" {
#endif

size_t read_console(bool password, char *buffer, size_t maxlen);

#ifdef __cplusplus
}
#endif

#endif
