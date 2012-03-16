#!/usr/bin/env python
import sys
import os
import glob

def read_log_file(log_file):
    f = open(log_file)
    header = [f.readline().strip() for _ in range(10)]
    header = [l for l in header if l.startswith("#")]
    if not header:
        return
    fields = [ l for l in header if l.startswith("#fields")][0]
    fields = fields.replace("#fields\t",'').split("\t")
    return fields

def read_log_files(log_files):
    logs = {}
    for f in log_files:
        info = read_log_file(f)
        if info:
            logs[f] = info
    return logs

def generate(log_dir, out_dir):
    log_files = glob.glob(os.path.join(log_dir, "*"))

    data = read_log_files(log_files)

    i = open(os.path.join(out_dir, "inputs.conf"),'w')
    p = open(os.path.join(out_dir, "props.conf"),'w')
    t = open(os.path.join(out_dir, "transforms.conf"),'w')

    for fn, fields in sorted(data.items()):
        print fn
        sourcetype = "bro_" + os.path.basename(fn).replace(".log",'')
        fields_str = ', '.join(['"%s"' % f for f in fields])

        i.write('[monitor://%s]\n' % fn)
        i.write('disabled = false\n')
        i.write('sourcetype = %s\n' % sourcetype )
        i.write('index=security\n\n')

        p.write('[%s]\n' % sourcetype)
        p.write('KV_MODE = none\n')
        p.write('SHOULD_LINEMERGE = false\n')
        p.write('given_type = csv\n')
        p.write('pulldown_type = true\n')
        p.write('REPORT-AutoHeader = AutoHeader-%s\n\n' % sourcetype)

        t.write('[AutoHeader-%s]\n' % sourcetype)
        t.write('DELIMS = "\t"\n')
        t.write('FIELDS = %s\n\n' % fields_str)

if __name__ == "__main__":
    log_dir = sys.argv[1]
    out_dir = sys.argv[2]

    generate(log_dir, out_dir)
