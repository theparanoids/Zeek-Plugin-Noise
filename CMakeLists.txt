
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(Zeek NOISE)
    zeek_plugin_cc(src/NOISE.cc src/Plugin.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/noise.pac src/noise-analyzer.pac src/noise-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()
