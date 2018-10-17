#!/usr/bin/env python

import glob
import imp
import os
import sys

def determine_testcases():
    tcs = []
    py_files = []
    
    if len(sys.argv) > 1:
        py_files = sys.argv[1:]
    else:
        py_files = glob.glob('tests/[0-9]*.py')
        
    print py_files
    for f in py_files:
        modname = os.path.basename(f).replace('.py', '')
        mod = imp.load_source(modname, f)
        for attr in dir(mod):
            if 'TestCase' in attr:
                tcs.append([mod, attr])
            
    return tcs

def main():

    for (mod, tc_class) in determine_testcases():
            testcase = getattr(mod, tc_class)()
            testcase.setup()
            try:
                testcase.main()
            finally:
                testcase.teardown()

if __name__ == '__main__':
    main()
