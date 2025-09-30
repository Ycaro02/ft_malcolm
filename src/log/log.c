#include "../../include/log.h"

/**
 * @brief Get the current log level
 * @return Pointer to the current log level variable
 */
u8 *get_log_level() {
	static u8 level = 0;
	return (&level);
}

/**
 * @brief Set the log level
 * @param level The log level to set
 */
void set_log_level(u8 level) {
	*get_log_level() = level;
}

/**
 * @brief Check if the provided log level string is valid and set the log level
 * @param str The log level string to check
 * @return s8 TRUE if the log level is valid and set, FALSE otherwise
 */
static s8 is_correct_log_level_str(char *str) {
    LogVerbosity valid_levels[] = LOG_VERBOSITY_LEVELS;
    char *to_lower_str = ft_strdup(str);
    s32 i = 0;

    while (str && str[i]) {
        to_lower_str[i] = ft_tolower(str[i]);
        i++;
    }

    for (s32 i = 0; i < (s32)NB_LOG_VERBOSITY_LEVEL; i++) {
        if (ft_strcmp(to_lower_str, valid_levels[i].level_str) == 0) {
            set_log_level(valid_levels[i].level);
            free(to_lower_str);
            INFO("Log level set to %s\n", valid_levels[i].level_str);
            return (TRUE);
        }
    }
    free(to_lower_str);
    ERR("Invalid log level: %s\n", str);
    return (FALSE);
}

/**
 * @brief Parse and set the log verbosity level from a string
 * @param opt_ptr Pointer to the option (not used), here to match the function signature of set_flag_option
 * @param data Pointer to the log level string
 * @return s8 TRUE if the log level is valid and set, FALSE otherwise
 */
s8 parse_log_verbosity(void *opt_ptr, void *data) {
    
    (void)opt_ptr;
    
    char    *str = data;
    s32     str_len = 0;

    DBG("Parsing log verbosity -> [%s]\n", str);

    if (!str) { goto error_case; }
    
    str_len = ft_strlen(str);
    
    if (str_len == 0) { goto error_case; }

    if (str_len == 1) {
        if (str[0] < '1' || str[0] > '4') {
            ERR("Invalid log level: %s\n", str);
            goto error_case;
        }
        u8 level = (u8)(str[0] - '0');
        set_log_level(level);
        INFO("Log level set to %s\n", LOG_VERBOSITY_LEVELS[level].level_str);
        return (TRUE);
    }

    return (is_correct_log_level_str(str));

    error_case:
        return (FALSE);

}
