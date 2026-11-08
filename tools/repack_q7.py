"""Lossless Q7 block round-trip and bounded same-size offline patch/repack.

Preserves package/ELF layout, compiled tables and original token choices where
valid. Invalidated copies become literals, including cross-block references;
an overflowing block can retokenize bounded windows with its original tables.
This is an offline research artifact builder, not an updater or flasher.
"""
import argparse
import hashlib
import json
import struct
from contextlib import suppress
from pathlib import Path

from build_analysis_elf import PLAIN, DECODED, assemble
from decode_segments import BITS, HEADER, inspect, decode_block, table_symbol
from q7_symbols import SHA

PRIVATE=Path(__file__).resolve().parents[1]/'.private'


def private_output(path):
    resolved=path.resolve()
    if not resolved.is_relative_to(PRIVATE.resolve()) or resolved==PRIVATE.resolve():
        raise ValueError('firmware artifacts must remain in a new directory under .private')
    if resolved.exists(): raise ValueError('output directory must not exist')
    return resolved


def digest(data):
    return hashlib.sha256(data).hexdigest()


def footer_check(data):
    if len(data)<32:
        raise ValueError('update is shorter than its footer')
    footer=data[-32:]
    ids=[footer[i:i+8].split(b'\0',1)[0].decode('ascii') for i in (0,8,16)]
    stored=struct.unpack_from('<I',footer,24)[0]
    calculated=sum(data[:-32])&0xffffffff
    return dict(identifiers=ids, stored_sum=stored, calculated_sum=calculated,
                sum_matches=stored==calculated, version_bytes=list(footer[28:]))


def literal_codes(table):
    """Invert bounded table prefixes; never invent a symbol absent from a table."""
    codes={}
    for prefix in range(1<<15):
        bits=f'{prefix:015b}'+'0'*32
        cursor=0
        def peek(n):
            if n<0 or cursor+n>len(bits):
                raise ValueError('invalid compiled table prefix')
            return int(bits[cursor:cursor+n],2) if n else 0
        def take(n):
            nonlocal cursor
            value=peek(n);cursor+=n
            return value
        try:
            word=table_symbol(table,True,take,peek)
        except ValueError:
            continue
        if cursor<=15 and word<0x400:
            value=word>>2;code=bits[:cursor]
            if value not in codes or (len(code),code)<(len(codes[value]),codes[value]):
                codes[value]=code
    return codes


def pack_bits(bits, capacity):
    if len(bits)>8*capacity:
        raise ValueError(f'recompressed payload needs {(len(bits)+7)//8} bytes; slot has {capacity}')
    bits += '0'*(-len(bits)%8)
    payload=bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))
    return payload+bytes(capacity-len(payload))


def rebuild_stream(data, segment, target, patch_ranges=()):
    target=bytes(target)
    original=bytearray();body=bytearray();changed=[];total_tokens=0
    for index, block in enumerate(segment['blocks']):
        start,end=block['file_offset'],block['file_end']
        kind,size,packed,nlit,ndist=HEADER.unpack_from(data,start)
        table_start=start+HEADER.size; bit_start=table_start+nlit+ndist
        literal=struct.unpack_from(f'<{nlit//4}I',data,table_start)
        distance=struct.unpack_from(f'<{ndist//4}I',data,table_start+nlit)
        bits=''.join(BITS[x] for x in data[bit_start:end])
        tokens=[];base=len(original)
        used=decode_block(literal,distance,data[bit_start:end],original,size,tokens)
        if len(target)<len(original):
            raise ValueError('replacement segment is too short')
        # shortcut: preserve tables and slots; general table regeneration/size changes
        # require a separate relocation and hardware-format validation milestone.
        parts=[];rows=[];pos=base;repairs=0;codes=None
        for token,value,dist,lo,hi in tokens:
            if token=='end':
                rows.append((pos,pos,True,bits[lo:hi]))
                parts.append(bits[lo:hi]);continue
            length=1 if token=='literal' else value
            if token=='literal':
                valid=target[pos]==value
            else:
                history=target[pos-dist:pos]
                valid=target[pos:pos+length]==(history*((length+dist-1)//dist))[:length]
            if valid:
                parts.append(bits[lo:hi])
            else:
                if codes is None: codes=literal_codes(literal)
                try:
                    parts.extend(codes[x] for x in target[pos:pos+length])
                except KeyError as exc:
                    raise ValueError(f'block {index}: replacement literal {exc.args[0]} absent from table') from exc
                repairs+=1
            rows.append((pos,pos+length,valid,bits[lo:hi]))
            pos+=length
        if pos!=base+size:
            raise ValueError('token coverage mismatch')
        encoded=''.join(parts)
        repair_info={}
        if len(encoded)>8*packed and patch_ranges:
            from fixed_table_encode import repair_windows
            baseline=len(encoded)
            encoded,repair_info=repair_windows(target,rows,patch_ranges,literal,distance,codes)
            repair_info.update(method='fixed-table repair windows',literal_repair_bits=baseline)
            check=bytearray(target[:base])
            payload=pack_bits(encoded,packed)
            consumed=decode_block(literal,distance,payload,check,size)
            if consumed!=len(encoded) or check!=target[:base+size]:
                raise ValueError('fixed-table repair verification failed')
        new=HEADER.pack(kind,size,packed,nlit,ndist)+data[table_start:bit_start]+pack_bits(encoded,packed)
        if len(new)!=end-start:
            raise ValueError('block size changed')
        if new!=data[start:end]:
            changed.append(dict(block=index,file_offset=start,file_end=end,
                                original_bits=used,new_bits=len(encoded),repaired_tokens=repairs,**repair_info))
        body+=new;total_tokens+=len(tokens)
    if len(target)!=len(original):
        raise ValueError('replacement segment length changed')
    return bytes(body),changed,total_tokens


def patch_plan(patches, regions):
    plan=[]
    for patch in patches:
        if set(patch)-{'va','expected_hex','replacement_hex','label'}:
            raise ValueError('unknown patch field')
        va=int(patch['va'],0)
        old,new=bytes.fromhex(patch['expected_hex']),bytes.fromhex(patch['replacement_hex'])
        if not old or len(old)!=len(new):
            raise ValueError('only nonempty same-size replacements are supported')
        region=next((r for r in regions if r[1]<=va and va+len(old)<=r[1]+len(r[2])),None)
        if region is None:
            raise ValueError(f'unmapped patch {va:#x}')
        if region[2][va-region[1]:va-region[1]+len(old)]!=old:
            raise ValueError(f'expected bytes do not match at {va:#x}')
        if any(va<b+len(n) and b<va+len(new) for _,b,n in plan):
            raise ValueError('overlapping patches')
        plan.append((region[0],va,new))
    return plan


def rebuild(firmware, patches):
    if digest(firmware)!=SHA:
        raise ValueError('expected the SHA-pinned original Q7 v1.01 update')
    before=footer_check(firmware)
    if not before['sum_matches']:
        raise ValueError('original footer checksum mismatch')
    manifest,decoded=inspect(firmware)
    regions=[(f'plain{i}',va,bytearray(firmware[off:off+size])) for i,(off,va,size) in enumerate(PLAIN)]
    regions += [(name,seg['virtual_address'],bytearray(decoded[name])) for seg in manifest['segments'] for name in (seg['name'],)]
    plan=patch_plan(patches,regions)
    for name,va,new in plan:
        region=next(r for r in regions if r[0]==name)
        region[2][va-region[1]:va-region[1]+len(new)]=new
    result=bytearray(firmware);reports=[]
    for seg in manifest['segments']:
        target=next(r[2] for r in regions if r[0]==seg['name'])
        ranges=[(va-seg['virtual_address'],va-seg['virtual_address']+len(new))
                for name,va,new in plan if name==seg['name']]
        body,changed,tokens=rebuild_stream(firmware,seg,target,ranges)
        result[seg['file_offset']:seg['file_end']]=body
        reports.append(dict(name=seg['name'],blocks=seg['block_count'],tokens=tokens,
                            changed_blocks=changed,decoded_sha256=digest(target)))
    for i,(off,va,size) in enumerate(PLAIN):
        result[off:off+size]=next(r[2] for r in regions if r[0]==f'plain{i}')
    struct.pack_into('<I',result,len(result)-8,sum(result[:-32])&0xffffffff)
    after,actual=inspect(result)
    for seg in manifest['segments']:
        expected=next(bytes(r[2]) for r in regions if r[0]==seg['name'])
        if actual[seg['name']]!=expected:
            raise ValueError('redecoded output mismatch')
    for a,b in zip(manifest['segments'],after['segments']):
        for key in ('file_offset','file_end','virtual_address','decoded_size','blocks'):
            if key!='blocks' and a[key]!=b[key]:
                raise ValueError('segment layout changed')
        for x,y in zip(a['blocks'],b['blocks']):
            if {k:v for k,v in x.items() if k!='used_bits'}!={k:v for k,v in y.items() if k!='used_bits'}:
                raise ValueError('block layout changed')
    elf=assemble([(va,bytes(buf)) for _,va,buf in regions])
    if not patches and bytes(result)!=firmware:
        raise ValueError('lossless package round-trip failed')
    report=dict(schema_version=1,input_sha256=SHA,output_sha256=digest(result),
                output_size=len(result),byte_identical=result==firmware,patches=patches,
                segment_results=reports,footer_before=before,footer_after=footer_check(result),
                analysis_elf_sha256=digest(elf),analysis_elf_size=len(elf),
                verification=['448 blocks reparsed and tokens serialized','all decoded bytes match requested regions',
                              'original file and ELF segment positions/sizes preserved','footer byte-sum recomputed'],
                limitations=['No package relocation, code insertion/deletion or general compressor is implemented.',
                             'Missing literal codes or payload capacity are rejected, never silently truncated.',
                             'The expanded ELF is for analysis only; not a camera image.',
                             'Footer checksum and software decoding do not prove updater, boot or camera acceptance.'])
    return bytes(result),elf,report


def write_outputs(output_dir, package, elf, report):
    """Write the report last and roll back files created by this invocation."""
    output_dir = private_output(output_dir)
    outputs = (
        ('research-update.bin', package),
        ('analysis-expanded.elf', elf),
        ('repack-report.json', (json.dumps(report, indent=2) + '\n').encode('utf-8')),
    )
    created = []
    output_dir.mkdir(parents=True)
    try:
        for name, data in outputs:
            path = output_dir / name
            with path.open('xb', buffering=0) as stream:
                created.append(path)
                written = stream.write(data)
                if written != len(data):
                    raise OSError(f'short write for {name}: expected {len(data)} bytes, wrote {written}')
    except BaseException:
        for path in reversed(created):
            with suppress(OSError):
                path.unlink()
        with suppress(OSError):
            output_dir.rmdir()
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware',type=Path)
    parser.add_argument('--patches',type=Path,help='JSON array of guarded same-size VA patches; omitted for lossless round-trip')
    parser.add_argument('--output-dir',type=Path,required=True,help='new private research directory')
    args=parser.parse_args()
    try: args.output_dir=private_output(args.output_dir)
    except ValueError as exc: parser.error(str(exc))
    patches=json.loads(args.patches.read_text(encoding='utf-8')) if args.patches else []
    if not isinstance(patches,list): parser.error('patches must be a JSON array')
    package,elf,report=rebuild(args.firmware.read_bytes(),patches)
    write_outputs(args.output_dir, package, elf, report)
    print(json.dumps({k:report[k] for k in ('input_sha256','output_sha256','byte_identical','analysis_elf_sha256')}))


if __name__=='__main__': main()
