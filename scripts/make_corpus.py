import pathlib, struct, zipfile, io, hashlib
root=pathlib.Path(__file__).resolve().parents[1]/'tests/corpus'
root.mkdir(parents=True,exist_ok=True)
# EICAR здесь намеренно не создаётся: тесты собирают его в памяти (см. tests/quality.cpp).
(root/'clean.txt').write_text('hello world\n')
(root/'jpeg.bin').write_bytes(b'\xff\xd8\xff\xe0'+bytes(range(256))*4)
(root/'mz.bin').write_bytes(b'MZ'+b'\0'*100)
b=bytearray(4096);b[:2]=b'MZ';struct.pack_into('<I',b,60,0xFFFFFFFD)
(root/'regression-lfanew.bin').write_bytes(b)
struct.pack_into('<I',b,60,64);b[64:68]=b'PE\0\0';struct.pack_into('<H',b,70,1);struct.pack_into('<H',b,84,224)
struct.pack_into('<H',b,88,0x10b);struct.pack_into('<I',b,104,0x1000);struct.pack_into('<I',b,180,16)
sh=312;b[sh:sh+8]=b'.text\0\0\0';struct.pack_into('<IIII',b,sh+8,512,0x1000,512,1024);struct.pack_into('<I',b,sh+36,0x60000020)
(root/'synthetic-pe.bin').write_bytes(b)
with zipfile.ZipFile(root/'clean.zip','w',zipfile.ZIP_DEFLATED) as z:z.writestr('sample.txt',b'hello')
with zipfile.ZipFile(root/'limit.zip','w',zipfile.ZIP_DEFLATED) as z:z.writestr('zeros.bin',b'\0'*(2<<20))
(root/'MANIFEST.sha256').write_text('\n'.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name for p in sorted(root.iterdir()) if p.is_file() and p.name!='MANIFEST.sha256' and not p.name.startswith('eicar'))+'\n')
print(root)
