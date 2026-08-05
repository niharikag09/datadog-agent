#ifndef THERMAL_DARWIN_H
#define THERMAL_DARWIN_H

#include <stdbool.h>

typedef struct {
    bool  hasValue;
    float value;
} OptionalFloat;

typedef struct {
    bool hasValue;
    int  value;
} OptionalInt;

// SmcInfo mirrors the Apple Silicon thermal sensors read via the AppleSMC
// user client. See notes/THERMAL_KNOWLEDGE.md and notes/SMC_BATTERY_SSD.md
// for the key tables and range filters behind each field.
typedef struct {
    OptionalFloat cpu;
    OptionalFloat gpu;
    OptionalFloat ssd;
    OptionalFloat battery;
} SmcInfo;

// HidInfo mirrors the Apple Silicon thermal sensors read via
// IOHIDEventSystemClient. battery here is the "gas gauge battery" HID node,
// a distinct reading from SmcInfo.battery (the TB0T-family SMC keys) — both
// are kept since either can be unavailable independently of the other. See
// notes/THERMAL_KNOWLEDGE.md for the sensor names and de-duplication rules
// behind each field.
typedef struct {
    OptionalFloat tdie;
    OptionalFloat nand;
    OptionalFloat battery;
    OptionalFloat mtrGpu;
    OptionalFloat mtrPacc;
    OptionalFloat mtrEacc;
    // The following are the hottest single node contributing to each
    // averaged field above, rather than the average across all matching
    // nodes.
    OptionalFloat tdieMax;
    OptionalFloat nandMax;
    OptionalFloat batteryMax;
    OptionalFloat mtrGpuMax;
    OptionalFloat mtrPaccMax;
    OptionalFloat mtrEaccMax;
} HidInfo;

typedef struct {
    SmcInfo smc;
    HidInfo hid;
    // thermalLevel is the raw macOS thermal pressure level (0=Nominal,
    // 1=Moderate, 2=Heavy, 3=Trapping, 4=Sleeping) read via the private
    // "com.apple.system.thermalpressurelevel" Darwin notification, with no
    // value if the notification lookup failed. See
    // notes/NOTIFY_THERMAL_STATE.md.
    OptionalInt thermalLevel;
} ThermalInfo;

ThermalInfo getThermalInfo(void);

#endif
