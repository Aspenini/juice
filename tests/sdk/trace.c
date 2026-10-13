/* Input for tracewpp (WPP software tracing). */
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(JuiceTrace, (8f6c5a10, 2b4e, 4d4a, 9a7f, 0c1d2e3f4a5b), \
        WPP_DEFINE_BIT(TRACE_INIT) \
        WPP_DEFINE_BIT(TRACE_IO))

#include "trace.tmh"

int work(int value) {
  DoTraceMessage(TRACE_INIT, "starting with %d", value);
  DoTraceMessage(TRACE_IO, "read %s, %u bytes", "file.bin", 42u);
  return value * 2;
}
