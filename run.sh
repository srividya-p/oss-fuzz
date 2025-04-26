#!/bin/bash

python3 infra/helper.py build_image mupdf --no-pull

python3 infra/helper.py build_fuzzers mupdf --sanitizer coverage --clean

mkdir -p build/out/bake_corpus

curr_time_2="`date "+%Y-%m-%d %H:%M:%S"`"
echo "INFO: Fuzzing started at: $curr_time_2"

python3 infra/helper.py run_fuzzer mupdf bake_fuzzer --corpus-dir build/out/bake_corpus \
    -e FUZZER_ARGS="-rss_limit_mb=2560 -timeout=25 -max_total_time=$(ptimesec 10m)"

python3 infra/helper.py coverage mupdf --corpus-dir build/out/bake_corpus --fuzz-target bake_fuzzer


# Useful commands:
# python3 infra/helper.py shell mupdf
# fuzz_target=validate_signature_fuzzer ./rebuild
# fuzz_target=bake_fuzzer ./rebuild
# fuzz_target=pdf_fuzzer ./rebuild

# Note: ptimesec is a local alias.
# function ptimesec(){
#         local time_str="$1"
#         echo "$time_str" | \
#         sed -E 's/([0-9]+)h/\1*3600+/g; s/([0-9]+)m/\1*60+/g; s/([0-9]+)s/\1+/g; s/\+$//' | \
#         bc
# }
