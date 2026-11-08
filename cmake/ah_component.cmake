# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
#
# The first-party warning set, as errors; vendored sources keep ESP-IDF's
# defaults. Each component includes this after idf_component_register, which
# ends the file during ESP-IDF's early requirements pass, so it applies only in
# the real one.
set(AH_WARNINGS -Wextra -Wshadow -Wformat=2 -Wvla -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Werror)

function(ah_first_party)
    set_source_files_properties(${ARGN} DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                                PROPERTIES COMPILE_OPTIONS "${AH_WARNINGS}")
endfunction()
