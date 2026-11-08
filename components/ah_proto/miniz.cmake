# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT

# How miniz is compiled, for the device component and the host build alike:
# inflate only, into caller memory. The node never deflates, opens files,
# allocates or reads the clock through miniz.
set(AH_MINIZ_DEFINES MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ZLIB_APIS MINIZ_NO_DEFLATE_APIS
                     MINIZ_NO_MALLOC)
