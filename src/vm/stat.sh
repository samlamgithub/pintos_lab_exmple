#! /bin/bash

grep -R PASS build/tests/ --include '*.result' | wc
grep -R PASS build/tests/ --include '*.result' -L

