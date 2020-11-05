#ifndef ZEEK_PLUGIN_ZEEK_NOISE
#define ZEEK_PLUGIN_ZEEK_NOISE

#include <plugin/Plugin.h>
#include "NOISE.h"

namespace plugin {
    namespace Zeek_NOISE {
        class Plugin : public ::plugin::Plugin {
            protected:
                // Overridden from plugin::Plugin.
                virtual plugin::Configuration Configure();
            };

        extern Plugin plugin;
        }
    }

#endif
