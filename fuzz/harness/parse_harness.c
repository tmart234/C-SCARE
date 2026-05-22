/* SPDX-License-Identifier: GPL-2.0-only
 *
 * parse_harness.c - AFL++ file-fuzzing harness TEMPLATE for a custom,
 * DICOM-parsing binary whose parser is a library call with no standalone
 * file mode.
 *
 * DCMTK itself ships dcmdump / dcmconv / dcm2pnm, which already serve as
 * parser entry points (see scripts/fuzz_parse.sh, campaign target "parse").
 * Use THIS template only for a *custom* binary, so AFL exercises exactly
 * your code path.
 *
 * Build it with the AFL compiler so the harness AND your parser are
 * instrumented together:
 *
 *   source scripts/install_afl.sh
 *   "$AFLPP_PATH/afl-clang-fast" -fsanitize=address -g \
 *       fuzz/harness/parse_harness.c -o fuzz/build-asan/parse_harness \
 *       -I/path/to/your/include -L/path/to/your/lib -lyourdicom
 *
 * Fuzz it:
 *   "$AFLPP_PATH/afl-fuzz" -i fuzz/seeds/file -o fuzz/out/custom \
 *       -- fuzz/build-asan/parse_harness @@
 *
 * (afl-clang-fast works for a harness you compile yourself; build_dcmtk.sh
 * uses afl-gcc only because clang's integrated assembler bypasses afl-as
 * when building DCMTK's own tree.)
 */
#include <stdio.h>
#include <stdlib.h>

/*
 * TODO: declare and link your binary's DICOM parse entry point.
 *
 * It must RETURN (never call exit()) so AFL can keep fuzzing; a crash or
 * ASan abort inside it is a finding.
 *
 * Example for a DCMTK-based parser using DcmFileFormat - rename this file
 * to parse_harness.cc and compile as C++:
 *
 *   #include "dcmtk/dcmdata/dcfilefo.h"
 *   extern "C" int harness_parse(const char *path) {
 *       DcmFileFormat ff;
 *       ff.loadFile(path);          // parses the whole dataset
 *       return 0;
 *   }
 */
extern int harness_parse(const char *path);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <dicom-file>\n", argv[0]);
        return 0;
    }
    return harness_parse(argv[1]);
}
