/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */

#include "message.h"

const char *mGetTypeStr(uint8_t type)
{
    switch(type)
    {
        case NOP:           return "NOP";
        case PING:          return "PING";
        case PONG:          return "PONG";
        case CHALLENGE:     return "CHALLENGE";
        case RESPONSE:      return "RESPONSE";
        case OPEN_CHANNEL:  return "OPEN_CHANNEL";
        case CLOSE_CHANNEL: return "CLOSE_CHANNEL";
        default:            return "UNKNOWN";
    }

    return "";
}
