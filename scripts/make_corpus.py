import pathlib, struct, zipfile, io, hashlib
root=pathlib.Path(__file__).resolve().parents[1]/'tests/corpus'
root.mkdir(parents=True,exist_ok=True)
eicar=(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$'+b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
assert len(eicar)==68
(root/'eicar.com').write_bytes(eicar)
(root/'clean.txt').write_text('hello world\n')
(root/'jpeg.bin').write_bytes(b'\xff\xd8\xff\xe0'+bytes(range(256))*4)
(root/'mz.bin').write_bytes(b'MZ'+b'\0'*100)
b=bytearray(4096);b[:2]=b'MZ';struct.pack_into('<I',b,60,0xFFFFFFFD)
(root/'regression-lfanew.bin').write_bytes(b)
struct.pack_into('<I',b,60,64);b[64:68]=b'PE\0\0';struct.pack_into('<H',b,70,1);struct.pack_into('<H',b,84,224)
struct.pack_into('<H',b,88,0x10b);struct.pack_into('<I',b,104,0x1000);struct.pack_into('<I',b,180,16)
sh=312;b[sh:sh+8]=b'.text\0\0\0';struct.pack_into('<IIII',b,sh+8,512,0x1000,512,1024);struct.pack_into('<I',b,sh+36,0x60000020)
(root/'synthetic-pe.bin').write_bytes(b)
for name,data in [('clean.zip',b'hello'),('eicar.zip',eicar)]:
 with zipfile.ZipFile(root/name,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('sample.txt',data)
with zipfile.ZipFile(root/'limit.zip','w',zipfile.ZIP_DEFLATED) as z:z.writestr('zeros.bin',b'\0'*(2<<20))
(root/'MANIFEST.sha256').write_text('\n'.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name for p in sorted(root.iterdir()) if p.is_file() and p.name!='MANIFEST.sha256')+'\n')
print(root)
