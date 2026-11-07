// Deterministic mutation smoke test; NOT coverage-guided libFuzzer.
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>
#include <random>
#include <iostream>
extern "C" int LLVMFuzzerTestOneInput(const unsigned char*,std::size_t);
int main(int argc,char** argv){if(argc!=2)return 4;std::mt19937 rng(17);std::size_t count=0;
 for(auto& p:std::filesystem::directory_iterator(argv[1])){
  if(!p.is_regular_file()||p.file_size()>65536)continue;
  std::ifstream f(p.path(),std::ios::binary);std::vector<unsigned char> seed{std::istreambuf_iterator<char>(f),{}};
  for(int i=0;i<1000;++i){auto b=seed;if(!b.empty()){
   for(unsigned j=0;j<1+rng()%8;++j)b[rng()%b.size()]=static_cast<unsigned char>(rng());
   if(i%5==0)b.resize(rng()%b.size());}
   LLVMFuzzerTestOneInput(b.data(),b.size());++count;
  }
 }
 std::cout<<"mutation smoke: "<<count<<" cases\n";
}
