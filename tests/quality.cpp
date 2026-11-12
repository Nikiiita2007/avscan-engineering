#include "engine.hpp"
#include "sha256.hpp"
#include "quarantine.hpp"
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

// EICAR собирается из двух частей прямо в памяти: файла с сигнатурой нет ни в репозитории, ни на диске,
// поэтому антивирус системы не удаляет его и не ломает тесты.
std::vector<std::uint8_t> eicarBytes() {
    const std::string head = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    const std::string tail = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const std::string s = head + tail;
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::uint32_t crc32Of(const std::vector<std::uint8_t>& d) {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::uint8_t b : d) {
        c ^= b;
        for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

void put16(std::vector<std::uint8_t>& o, unsigned v) {
    o.push_back(static_cast<std::uint8_t>(v & 0xFF));
    o.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void put32(std::vector<std::uint8_t>& o, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) o.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

// Минимальный ZIP с одной записью без сжатия (method 0), собирается в памяти.
std::vector<std::uint8_t> storedZip(const std::string& name, const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> z;
    const std::uint32_t crc = crc32Of(data);
    const std::uint32_t size = static_cast<std::uint32_t>(data.size());
    const unsigned nlen = static_cast<unsigned>(name.size());
    put32(z, 0x04034b50u); put16(z, 20); put16(z, 0); put16(z, 0); put16(z, 0); put16(z, 0x21);
    put32(z, crc); put32(z, size); put32(z, size); put16(z, nlen); put16(z, 0);
    z.insert(z.end(), name.begin(), name.end());
    z.insert(z.end(), data.begin(), data.end());
    const std::uint32_t cdStart = static_cast<std::uint32_t>(z.size());
    put32(z, 0x02014b50u); put16(z, 20); put16(z, 20); put16(z, 0); put16(z, 0); put16(z, 0); put16(z, 0x21);
    put32(z, crc); put32(z, size); put32(z, size); put16(z, nlen);
    put16(z, 0); put16(z, 0); put16(z, 0); put16(z, 0); put32(z, 0); put32(z, 0);
    z.insert(z.end(), name.begin(), name.end());
    const std::uint32_t cdSize = static_cast<std::uint32_t>(z.size()) - cdStart;
    put32(z, 0x06054b50u); put16(z, 0); put16(z, 0); put16(z, 1); put16(z, 1);
    put32(z, cdSize); put32(z, cdStart); put16(z, 0);
    return z;
}

} // namespace

int main(int argc,char** argv){
 if(argc!=3)return 4;
 int fails=0;
 auto check=[&](bool ok,const char* s){std::cout<<(ok?"PASS ":"FAIL ")<<s<<'\n';if(!ok)++fails;};
 av::Sha256 hash;check(hash.hexdigest()=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","SHA256 empty");
 std::vector<std::uint8_t> abc{'a','b','c'};av::Sha256 h;av::feed(h,abc);
 check(h.hexdigest()=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 abc, concept feed");
 av::Config config;config.useCache=false;config.limits.maxEntrySize=1<<20;
 auto engine=av::makeEngine(av::pathFromUtf8(argv[1]),config);check(bool(engine),"expected engine success");if(!engine)return 1;
 check(!av::makeEngine("_not_existing_db_"),"expected engine failure");
 auto corpus=av::pathFromUtf8(argv[2]);
 auto scan=[&](const char* p){return (*engine)->scanPath(av::pathUtf8(corpus/p));};
 auto scanMem=[&](const std::vector<std::uint8_t>& d,const char* n){av::Budget b;b.rootSize=d.size();return (*engine)->scanMemory(d,n,0,b);};
 check(scan("clean.txt").status==av::Status::Clean,"clean text");
 check(scan("jpeg.bin").status==av::Status::Clean,"JPEG not malware");
 check(scan("mz.bin").status==av::Status::Clean,"MZ not malware");
 const auto eicar=eicarBytes();
 check(eicar.size()==68,"EICAR is 68 bytes");
 check(scanMem(eicar,"eicar.com").status==av::Status::Infected,"EICAR 68 bytes (in memory)");
 auto r=scan("regression-lfanew.bin");check(r.status!=av::Status::Infected,"e_lfanew overflow regression");
 check(scan("synthetic-pe.bin").type==av::FileType::PE,"synthetic PE parse");
 check(scan("missing.file").status==av::Status::Error,"missing file Error not Clean");
 if(av::archiveSupportFor(av::FileType::Zip)){
  check(scan("clean.zip").status==av::Status::Clean,"ZIP clean");
  check(scanMem(storedZip("sample.txt",eicar),"eicar.zip").status==av::Status::Infected,"ZIP EICAR (in memory)");
  auto limited=scan("limit.zip");check(limited.partial&&limited.status!=av::Status::Clean,"ZIP limit not Clean");
 }
 auto temp=std::filesystem::temp_directory_path()/("av-evidence-test-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
 av::Quarantine q(temp);auto copied=q.copyEvidence(corpus/"clean.txt");check(bool(copied),"evidence copy result");
 if(copied)check(std::filesystem::file_size(*copied/"sample.bin")==std::filesystem::file_size(corpus/"clean.txt"),"evidence size");
 check(std::filesystem::exists(corpus/"clean.txt"),"source preserved");std::error_code ec;std::filesystem::remove_all(temp,ec);
 return fails?1:0;
}
