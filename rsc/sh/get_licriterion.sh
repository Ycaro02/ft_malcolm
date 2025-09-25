#!/bin/bash

wget https://github.com/Snaipe/Criterion/releases/download/v2.4.2/criterion-2.4.2-linux-x86_64.tar.xz
tar -xvf criterion-2.4.2-linux-x86_64.tar.xz && rm -f criterion-2.4.2-linux-x86_64.tar.xz
mkdir -p deps
mv criterion-2.4.2 deps
