#include "quarantine.hpp"
#include <iostream>
static int usage(){std::cerr
 <<"Usage:\n"
 <<"  avquarantine STORE FILE                store FILE as plaintext evidence (legacy; source NOT deleted)\n"
 <<"  avquarantine store STORE FILE          encrypt FILE into STORE (AES-256-CBC, DPAPI key, deny-execute ACL)\n"
 <<"  avquarantine restore STORE ID DEST     decrypt record ID back to DEST\n"
 <<"  avquarantine remove STORE ID           wipe (overwrite) and delete record ID\n"
 <<"  avquarantine list STORE                list records\n"
 <<"(encrypted store requires Windows; restore needs the same machine/account as store)\n";return 4;}
int main(int argc,char** argv){
 try{
  std::string cmd=(argc>=2)?argv[1]:"";
  if(cmd=="store"&&argc==4){
   av::Quarantine q(av::pathFromUtf8(argv[2]));
   auto r=q.store(av::pathFromUtf8(argv[3]));
   if(!r){std::cerr<<r.error().message<<'\n';return 3;}
   std::cout<<*r<<'\n';return 0;
  }
  if(cmd=="restore"&&argc==5){
   av::Quarantine q(av::pathFromUtf8(argv[2]));
   auto r=q.restore(argv[3],av::pathFromUtf8(argv[4]));
   if(!r){std::cerr<<r.error().message<<'\n';return 3;}
   std::cout<<"restored "<<argv[3]<<" -> "<<argv[4]<<'\n';return 0;
  }
  if(cmd=="remove"&&argc==4){
   av::Quarantine q(av::pathFromUtf8(argv[2]));
   auto r=q.remove(argv[3]);
   if(!r){std::cerr<<r.error().message<<'\n';return 3;}
   std::cout<<"removed "<<argv[3]<<'\n';return 0;
  }
  if(cmd=="list"&&argc==3){
   av::Quarantine q(av::pathFromUtf8(argv[2]));
   auto r=q.list();
   if(!r){std::cerr<<r.error().message<<'\n';return 3;}
   for(auto& rec:*r)std::cout<<rec.id<<'\t'<<rec.cipherBytes<<'\t'<<rec.source<<'\n';
   return 0;
  }
  if(argc==3){ // legacy: STORE FILE (plaintext evidence)
   av::Quarantine q(av::pathFromUtf8(argv[1]));
   auto r=q.copyEvidence(av::pathFromUtf8(argv[2]));
   if(!r){std::cerr<<r.error().message<<'\n';return 3;}
   std::cout<<av::pathUtf8(*r)<<'\n';return 0;
  }
 }catch(std::exception& e){std::cerr<<e.what()<<'\n';return 3;}
 return usage();
}
