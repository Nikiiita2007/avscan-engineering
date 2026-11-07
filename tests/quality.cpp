#include "engine.hpp"
#include "sha256.hpp"
#include "quarantine.hpp"
#include <fstream>
#include <iostream>
#include <chrono>
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
 check(scan("clean.txt").status==av::Status::Clean,"clean text");
 check(scan("jpeg.bin").status==av::Status::Clean,"JPEG not malware");
 check(scan("mz.bin").status==av::Status::Clean,"MZ not malware");
 check(scan("eicar.com").status==av::Status::Infected,"EICAR 68 bytes");
 auto r=scan("regression-lfanew.bin");check(r.status!=av::Status::Infected,"e_lfanew overflow regression");
 check(scan("synthetic-pe.bin").type==av::FileType::PE,"synthetic PE parse");
 check(scan("missing.file").status==av::Status::Error,"missing file Error not Clean");
 if(av::archiveSupportFor(av::FileType::Zip)){
  check(scan("clean.zip").status==av::Status::Clean,"ZIP clean");check(scan("eicar.zip").status==av::Status::Infected,"ZIP EICAR");
  auto limited=scan("limit.zip");check(limited.partial&&limited.status!=av::Status::Clean,"ZIP limit not Clean");
 }
 auto temp=std::filesystem::temp_directory_path()/("av-evidence-test-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
 av::Quarantine q(temp);auto copied=q.copyEvidence(corpus/"clean.txt");check(bool(copied),"evidence copy result");
 if(copied)check(std::filesystem::file_size(*copied/"sample.bin")==std::filesystem::file_size(corpus/"clean.txt"),"evidence size");
 check(std::filesystem::exists(corpus/"clean.txt"),"source preserved");std::error_code ec;std::filesystem::remove_all(temp,ec);
 return fails?1:0;
}
