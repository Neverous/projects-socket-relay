/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket-relay.
 * ----------
 *  Server node.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

// Usage options and info
const char *VERSION = "0.1.0";
const char *HELP    = "Usage: socket-server [options]\n\n\
    -h --help                               Display this usage information.\n\
    -v --version                            Display program version.\n\
    -r --relay-host     HOST[=localhost]    Address of the relay.\n\
    -s --host           HOST[=localhost]    Destination address.\n\
    -c --control-port   PORT[=10000]        Control port of the relay.\n\
    -d --data-port      PORT[=10001]        Data port of the relay.\n\
    -p --password       PASSWORD[=1234]     Password.";

const char *SHORT_OPTIONS           = "hvr:s:c:d:p:";
const struct option LONG_OPTIONS[] =
{
    {"help",            no_argument,        NULL,   'h'}, // display help and usage information
    {"version",         no_argument,        NULL,   'v'}, // display version
    {"relay-host",      required_argument,  NULL,   'r'}, // relay address
    {"host",            required_argument,  NULL,   's'}, // destination address
    {"control-port",    required_argument,  NULL,   'c'}, // relay control port
    {"data-port",       required_argument,  NULL,   'd'}, // relay data port
    {"password",        required_argument,  NULL,   'p'}, // password
    {NULL, 0, 0, 0},
};

struct Options
{
    int16_t     controlPort;
    int16_t     dataPort;
    const char  *relayHost;
    const char  *host;
    const char  *password;
} options = {
    10000,
    10001,
    "localhost",
    "localhost",
    "1234",
};

int32_t main(int32_t argc, char **argv)
{
    int32_t o;
    while((o = getopt_long(argc, argv, SHORT_OPTIONS, LONG_OPTIONS, NULL)) != -1) switch(o)
    {
        case 'h': puts(HELP);
            return 0;

        case 'v': printf("socket-server %s\n", VERSION);
            return 0;

        case 'r': options.relayHost = optarg;
            break;

        case 's': options.host = optarg;
            break;

        case 'c': options.controlPort = atoi(optarg);
            break;

        case 'd': options.dataPort = atoi(optarg);
            break;

        case 'p': options.password = optarg;
            break;

        case '?': fputs(HELP, stderr);
            return 1;
    }

    return 2;
}
