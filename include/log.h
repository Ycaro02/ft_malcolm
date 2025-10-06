#ifndef LOG_DECLARE_H
#define LOG_DECLARE_H

#include <stdio.h>
#include "../libft/libft.h"

/* Log message level */
typedef enum {
	L_NONE,			/* No log */
	L_ERROR,		/* Error log */
	L_WARN,		    /* Warning log */
    L_INFO,			/* Info log */
	L_DEBUG			/* Debug log */
} LogLevel;

/* Log Verbosity structure */
struct log_verbosity {
    u8      level;          /* Verbosity level */
    char    *level_str;     /* Verbosity level as string */
};

/* Typedef for LogVerbosity structure */
typedef struct log_verbosity LogVerbosity;

/* Define log verbosity levels array */
#define LOG_VERBOSITY_LEVELS (LogVerbosity[]){ \
    {L_NONE, "none"}, \
    {L_ERROR, "error"}, \
    {L_WARN, "warn"}, \
    {L_INFO, "info"}, \
    {L_DEBUG, "debug"} \
}

#define NB_LOG_VERBOSITY_LEVEL (sizeof(LOG_VERBOSITY_LEVELS) / sizeof(struct log_verbosity))



/*----------------------------------------------------------------------------------*/
/*								src/log.c											*/
/*----------------------------------------------------------------------------------*/

/* Get the log level */
u8      *get_log_level();

/* Set the log level */
void    set_log_level(u8 level);

/* Check if the log level string is correct and set the log level (used in set_flag_option) */
s8      parse_log_verbosity(void *opt_ptr, void *data);

/* Log message */
#define LOG_MESSAGE(_color_, _level_, _format_str_, ...) do { \
	printf("[%s%s"RESET"]: "_format_str_, _color_, _level_, ##__VA_ARGS__); \
} while (0) \


/* Log macro */
#define LOG(_msg_level_, _format_str_, ...) do { \
	u8 _curr_level_ = *get_log_level(); \
	switch (_msg_level_) { \
		case L_ERROR: \
			if (_curr_level_ >= L_ERROR) \
				LOG_MESSAGE(RED, "ERR", _format_str_, ##__VA_ARGS__); \
			break; \
		case L_WARN: \
			if (_curr_level_ >= L_WARN) \
				LOG_MESSAGE(ORANGE, "WRN", _format_str_, ##__VA_ARGS__); \
			break; \
		case L_INFO: \
			if (_curr_level_ >= L_INFO) \
				LOG_MESSAGE(GREEN, "INF", _format_str_, ##__VA_ARGS__); \
			break; \
		case L_DEBUG: \
			if (_curr_level_ >= L_DEBUG) \
				LOG_MESSAGE(CYAN, "DBG", _format_str_, ##__VA_ARGS__); \
			break; \
		default: \
			break; \
	} \
} while (0) \

#define DBG(_format_str_, ...) do { \
    LOG(L_DEBUG, _format_str_, ##__VA_ARGS__); \
} while (0) \

#define INFO(_format_str_, ...) do { \
    LOG(L_INFO, _format_str_, ##__VA_ARGS__); \
} while (0) \

#define WARN(_format_str_, ...) do { \
    LOG(L_WARN, _format_str_, ##__VA_ARGS__); \
} while (0) \

#define ERR(_format_str_, ...) do { \
    LOG(L_ERROR, _format_str_, ##__VA_ARGS__); \
} while (0) \

#endif /* LOG_DECLARE_H */

