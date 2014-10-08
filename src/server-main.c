/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket-server.
 * ----------
 *  Simple server server.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>

#include "log/log.h"
#include "server/server.h"

// Usage options and info
const char *VERSION = "0.1.0";
const char *HELP    = "Usage: socket-server [options]\n\n\
    -h --help                           Display this usage information.\n\
    -V --version                        Display program version.\n\
    -v --verbose                        Increase verbosity level.\n\
    -d --debug LEVEL[=info]             Set verbosity level to LEVEL [error, warning, info, notice, debug].\n\
    -l --log FILE[=stderr]              Set log file.\n\
    -p --control-port PORT[=10000]      Control port of the server.\n\
    -q --connection-port PORT[=10001]   Connection port of the server.\n\
    -r --server-ports PORTS              Server ports.\n\
    -a --auth TOKEN[=1234]              Auth token.";

const char *SHORT_OPTIONS           = "hVvd:l:p:q:r:a:";
const struct option LONG_OPTIONS[] =
{
    {"help",            no_argument,        0, 'h'}, // display help and usage information
    {"version",         no_argument,        0, 'V'}, // display version
    {"verbose",         no_argument,        0, 'v'}, // set log level to notice
    {"debug",           required_argument,  0, 'd'}, // manually set log level [error, warning, info, notice, debug]
    {"log",             required_argument,  0, 'l'}, // set log file
    {"control-port",    required_argument,  0, 'p'}, // server control port
    {"connection-port", required_argument,  0, 'q'}, // server connection port
    {"server-ports",     required_argument,  0, 'r'}, // server ports
    {"auth",            required_argument,  0, 'a'}, // server auth token
    {NULL, 0, 0, 0},
};

SocketServer server = {
    {
        "localhost",
        10000,
        10001,
        "1234",
        "tcp:10080:80,tcp:10022:22",
    },
    {
        {0, {"", NULL, NULL}},
        0,
        0,
        0,
        {},
    },
    NULL,
    {LOG_INFO, 0},
};

uint32_t    loglevel;
char        *logfile;

void sigbreak(int signal)
{
    INFO(&server.log, "Caught signal. Closing.");
    sDisconnect(&server, "caught signal");;
    lClose(&server.log);
    exit(0);
}

int32_t main(int32_t argc, char **argv)
{
    srand(time(NULL));
    signal(SIGINT,  sigbreak);
    signal(SIGKILL, sigbreak);
    int32_t o;

    while((o = getopt_long(argc, argv, SHORT_OPTIONS, LONG_OPTIONS, 0)) != -1) switch(o)
    {
        case 'h': puts(HELP);
            return 0;

        case 'V': printf("socket-server %s\n", VERSION);
            return 0;

        case 'v': loglevel = LOG_NOTICE;
            break;

        case 'd':
            if(memcmp(optarg,       "error", 5) == 0)   loglevel = LOG_ERROR;
            else if(memcmp(optarg,  "warning", 7) == 0) loglevel = LOG_WARNING;
            else if(memcmp(optarg,  "info", 4) == 0)    loglevel = LOG_INFO;
            else if(memcmp(optarg,  "notice", 6) == 0)  loglevel = LOG_NOTICE;
            else if(memcmp(optarg,  "debug", 5) == 0)   loglevel = LOG_DEBUG;
            else                                        {fputs(HELP, stderr); return 1;}
            break;

        case 'l': logfile = optarg;
            break;

        case 'p': server.control.port = atoi(optarg);
            break;

        case 'q': server.control.connectionPort = atoi(optarg);
            break;

        case 'a': server.control.password = optarg;
            break;

        case 'r': server.control.ports = optarg;
            break;

        case '?': fputs(HELP, stderr);
            return 1;
    }

    lOpen(&server.log, logfile, loglevel);
    NOTICE(&server.log, "Socket-server server configured with %u, %u control ports and %s server ports.", server.control.port, server.control.connectionPort, server.control.ports);
    if(!sConnect(&server))
    {
        lClose(&server.log);
        return 2;
    }

    if(!sOpenPorts(&server))
    {
        lClose(&server.log);
        return 3;
    }

    sListen(&server);
    sDisconnect(&server, "server exit");
    lClose(&server.log);
    return 0;
}
