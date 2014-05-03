#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define MODULE_NAME           "pam_truecrypt"
#define PAM_TRUECRYPT_AUTHTOK "pam_truecrypt_authtok"
#define TRUECRYPT             "/usr/bin/truecrypt"

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#define ERROR -1
#define FALSE  0
#define TRUE   1

// indexes in argv in pam_sm_authenticate() and pam_sm_open_session()
#define USER 0
#define DEVICE 1
#define MOUNTPOINT 2

/*
 * log function, as in pam_listfile.c
 */
void my_log(int level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    openlog("pam_truecrypt", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(level, format, args);
    va_end(args);
    closelog();
}

/*
 * wrapper for pam_get_item, checks for errors and logs errors.
 *
 * return:
 *     NULL    : if the item was NULL or empty
 *     the item: otherwise
 */
char *my_get_item(pam_handle_t *pamh, int item_type, char *item_name) {
    char *result;
    int retval = pam_get_item(pamh, item_type, (const void **) &result);
    if (retval != PAM_SUCCESS) {
        my_log(LOG_ERR, "cannot access %s: %s", item_name, pam_strerror(pamh,retval));
        return NULL;
    }
    if ( result == NULL ) {
        my_log(LOG_ERR, "%s is NULL.", item_name);
        return NULL;
    }
    if ( strlen(result) <= 0 ) {
        my_log(LOG_ERR, "%s is empty.", item_name);
        return NULL;
    }
    return result;
}

/*
 * Simple grep, without any regular expressions.
 *
 * return:
 *    -1 (ERROR): error (error message is logged using syslog)
 *     1 (TRUE) : string is found in file
 *     0 (FALSE): string is not found in file
 */
int grep(const char *string, const char *filename) {
    int bufsize = strlen(string);
    char ringbuf[bufsize];
    int i, fd, res, offset, match;
    if ( (fd = open(filename, O_RDONLY)) < 0 ) {
        my_log(LOG_ERR, "%s: %s", filename, strerror(errno));
        return ERROR;
    }
    if ( (res = read(fd, ringbuf, bufsize)) < 0 ) {
        my_log(LOG_ERR, "%s: %s", filename, strerror(errno));
        close(fd);
        return ERROR;
    }
    if ( res < bufsize ) {
        close(fd);
        return FALSE;
    }
    offset = 0;
    while ( res != 0 ) { // end of file
        match = 1;
        for ( i=0; i<bufsize; i++ ) {
            if ( ringbuf[(i+offset)%bufsize] != string[i] ) {
                match = 0;
                break;
            }
        }
        if ( match ) {
            close(fd);
            return TRUE; // string found
        }
        res = read(fd, ringbuf + offset, 1);
        offset = (offset + 1) % bufsize;
    }
    close(fd);
    return FALSE; // string not found
}

/*
 * check in /proc/mounts if homedir is already mounted
 * return:
 *    -1 (ERROR): error
 *     0 (FALSE): homedir is not mounted
 *     1 (TRUE) : homedir is already mounted
 */
int homedir_already_mounted(const char *homedir) {
    int result = grep(homedir, "/proc/mounts");
    return result;
}

/*
 * Check if the parameters are NULL or empty strings.
 * Returns TRUE or FALSE
 */
int parms_empty(const char *device, const char *mountpoint,
        const char *passwd) {
    if ( device == NULL || mountpoint == NULL ) {
        my_log(LOG_ERR, "configuration error");
        return TRUE;
    }
    if ( strlen(device) <= 0 || strlen(mountpoint) <= 0 ) {
        my_log(LOG_ERR, "configuration error");
        return TRUE;
    }
    if ( passwd == NULL ) {
        my_log(LOG_ERR, "cannot access authentication token (password)");
        return TRUE;
    }
    if ( strlen(passwd) <= 0 ) {
        my_log(LOG_ERR, "cannot access authentication token (password)");
        return TRUE;
    }
    return FALSE;
}

/*
 * write password to fd
 */
int write_password_to_pipe(int fd, const char *password) {
    int pwdlen = strlen(password); // >= 1, because parms_not_empty()
    if ( write(fd, password, pwdlen) != pwdlen ) {
        my_log(LOG_ERR, "write to pipe failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    if ( write(fd, "\n", 1) != 1 ) {
        my_log(LOG_ERR, "write to pipe failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

/*
 * wrapper for watipid(). Checks for errors.
 * returns an error if child process returns a status != 0
 */
int wait_for_child(pid_t pid) {
    int status;
    if ( waitpid(pid, &status, 0) < 0 ) {
        my_log(LOG_ERR, "failed to wait for truecrypt process: %s",
            strerror(errno));
        return PAM_AUTH_ERR;
    }
    if ( ! WIFEXITED(status) ) {
        my_log(LOG_ERR, "truecrypt did not terminate normally.");
        return PAM_AUTH_ERR;
    }
    if ( ! WEXITSTATUS(status) == 0 ) {
        my_log(LOG_ERR, "truecrypt returned exit status %d",
            WEXITSTATUS(status));
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

/*
 * fork truecrypt process and wait until it's terminated
 */
int run_truecrypt(const char *device, const char *mountpoint,
        const char *password) {
    int fd[2];
    pid_t pid;
    int retval;
    enum { READ, WRITE };
    // PATH must contain insmod and mount
    char * environment[] = { "PATH=/sbin:/bin", (char *) NULL };

    if ( parms_empty(device, mountpoint, password) ) {
        my_log(LOG_ERR, "cannot access parameters");
        return PAM_AUTH_ERR;
    }

    // see Stevens: Advanced Programming in the Unix Environment

    if ( pipe(fd) < 0 ) {
        my_log(LOG_ERR, "pipe failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    if ( (pid = fork()) < 0 ) {
        my_log(LOG_ERR, "fork failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    if ( pid > 0 ) { // parent
        if ( close(fd[READ]) < 0 ) {
            my_log(LOG_ERR, "cannot close read-end of pipe: %s", strerror(errno));
            return PAM_AUTH_ERR;
        }
        if ( write_password_to_pipe(fd[WRITE], password) != PAM_SUCCESS ) {
            return PAM_AUTH_ERR;
        }
        if ( close(fd[WRITE]) < 0 ) {
            my_log(LOG_ERR, "cannot close write-end of pipe: %s", strerror(errno));
            return PAM_AUTH_ERR;
        }
        if ( wait_for_child(pid) != PAM_SUCCESS ) {
            return PAM_AUTH_ERR;
        }
    }
    else { // child is the truecrypt process
        if ( close(fd[WRITE]) < 0 ) {
            my_log(LOG_ERR, "cannot close write-end of pipe: %s", strerror(errno));
            exit(-1);
        }
        if ( fd[READ] != STDIN_FILENO ) {
            if ( dup2(fd[READ], STDIN_FILENO) != STDIN_FILENO ) {
                my_log(LOG_ERR, "dup2 error to stdin: %s", strerror(errno));
                exit(-1);
            }
            if ( close(fd[READ]) < 0 ) {
                my_log(LOG_ERR, "cannot close read-end of pipe: %s",strerror(errno));
                exit(-1);
            }
        }
        retval = execle(TRUECRYPT, TRUECRYPT, device, mountpoint, (char *) NULL, environment);
        if ( retval < 0 ) {
            my_log(LOG_ERR, "cannot execute %s", TRUECRYPT);
            exit(-1);
        }
    }
    return PAM_SUCCESS;
}

/*
 * Does not really authenticate, but stores the password in pamh.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh,
        int flags, int argc, const char **argv)
{
    char *authtok, *user;
    int retval;
    if ( argc != 3 ) {
        my_log(LOG_ERR, "configuration error for module pam_truecrypt.");
        return PAM_AUTH_ERR;
    }
    if ((user = my_get_item(pamh, PAM_USER, "user")) == NULL) {
        return PAM_AUTH_ERR;
    }
    if ( strcmp(argv[USER], user) != 0 ) { // nothing to do
        return PAM_SUCCESS;
    }
    if ((authtok = my_get_item(pamh, PAM_AUTHTOK, "password")) == NULL) {
        return PAM_AUTH_ERR;
    }
    authtok = strdup(authtok); // allocate copy, must be free()d manually later
    retval = pam_set_data(pamh, PAM_TRUECRYPT_AUTHTOK, authtok, NULL);
    if ( retval != PAM_SUCCESS ) {
        my_log(LOG_ERR, "pam_set_data: %s\n", pam_strerror(pamh, retval));
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

/*
 * overwrite and free() authtok
 */
void cleanup(char *authtok) {
    int i = 0;
    while ( authtok[i] != '\0' ) {
        authtok[i++] = '\0';
    }
    free(authtok);
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
        int argc, const char **argv)
{
    int retval;
    char *authtok, *user;
    if ( argc != 3 ) {
        my_log(LOG_ERR, "configuration error for module pam_truecrypt.");
        return PAM_AUTH_ERR;
    }
    if ((user = my_get_item(pamh, PAM_USER, "user")) == NULL) {
        return PAM_AUTH_ERR;
    }
    if ( strcmp(argv[USER], user) != 0 ) { // nothing to do
        return PAM_SUCCESS;
    }
    retval = pam_get_data(pamh, PAM_TRUECRYPT_AUTHTOK, (const void **)&authtok);
    if ( retval != PAM_SUCCESS ) {
        my_log(LOG_ERR, "PAM_TRUECRYPT_AUTHTOK: %s", pam_strerror(pamh, retval));
        return PAM_AUTH_ERR;
    }
    switch ( homedir_already_mounted(argv[MOUNTPOINT]) ) {
        case ERROR:
            my_log(LOG_ERR, "could not access /proc/mounts");
            retval = PAM_AUTH_ERR;
            break;
        case TRUE: // nothing to do
            retval = PAM_SUCCESS;
            break;
        default:
            retval = run_truecrypt(argv[DEVICE], argv[MOUNTPOINT], authtok);
            if ( retval == PAM_SUCCESS ) {
                my_log(LOG_INFO, "%s: successfully mounted %s to %s",
                    argv[USER], argv[DEVICE], argv[MOUNTPOINT]);
            }
            break;
    }
    cleanup(authtok);
    return retval;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, int flags,
                                        int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
        const char **argv)
{
    return PAM_SUCCESS;
}

