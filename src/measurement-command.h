#ifndef VSCPD_MEASUREMENT_COMMAND_H
#define VSCPD_MEASUREMENT_COMMAND_H

#include <string>
#include <vscp.h>

bool parseMeasurementCommand(const std::string& arguments,
                             const uint8_t* interfaceGuid,
                             vscpEventEx& event);

#endif
