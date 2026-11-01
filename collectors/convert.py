"""Convert Zeek TSV or tshark JSON exports to bounded JSONL for SOC ingestion."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def convert(path, format):
    data = Path(path).read_bytes()
    if len(data)>50*1024*1024:
        raise ValueError('Export limit 50 MB; split source exports first')
    digest = hashlib.sha256(data).hexdigest()
    if format=='tshark-json':
        packets = json.loads(data)
        if not isinstance(packets,list) or len(packets)>10000:
            raise ValueError('Expected an array of at most 10000 packets')
        for packet in packets:
            layers = packet.get('_source',{}).get('layers',{})
            clean = {key:{k:v for k,v in layers.get(key,{}).items() if k in fields} for key,fields in {
                'frame':{'frame.time_epoch','frame.number','frame.len'},
                'ip':{'ip.src','ip.dst'}, 'tcp':{'tcp.srcport','tcp.dstport'},
                'udp':{'udp.srcport','udp.dstport'}}.items()}
            yield {'_source':{'layers':clean},'derived_from_sha256':digest}
    else:
        fields = None
        count = 0
        for line in data.decode('utf-8','strict').splitlines():
            if line.startswith('#separator ') and line!='#separator \\x09':
                raise ValueError('Only tab-separated Zeek TSV is supported')
            if line.startswith('#fields\t'):
                fields = line.split('\t')[1:]
            if not line or line.startswith('#'):
                continue
            if not fields:
                raise ValueError('Zeek #fields header required')
            values = line.split('\t')
            if len(values)!=len(fields):
                raise ValueError('Invalid Zeek column count')
            row = dict(zip(fields, values))
            for key in ('ts','id.orig_p','id.resp_p'):
                if row.get(key) not in (None,'-'):
                    row[key] = float(row[key]) if key=='ts' else int(row[key])
            row['derived_from_sha256'] = digest
            count += 1
            if count>10000:
                raise ValueError('Maximum 10000 records; split source exports first')
            yield row


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format',choices=['zeek-tsv','tshark-json'],required=True)
    parser.add_argument('input')
    parser.add_argument('output')
    args=parser.parse_args()
    # Validate all records before replacing the destination.
    lines=[json.dumps(row,ensure_ascii=False) for row in convert(args.input,args.format)]
    if any(len(line)>16384 for line in lines):
        parser.error('Converted record exceeds SOC line limit')
    Path(args.output).write_text('\n'.join(lines)+'\n',encoding='utf-8')


if __name__=='__main__':
    main()
