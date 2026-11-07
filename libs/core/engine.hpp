#pragma once
#include "scanner.hpp"
#include "result.hpp"
#include "modern.hpp"
#include <memory>
namespace av {
inline Result<std::unique_ptr<Scanner>> makeEngine(const std::filesystem::path& dbPath,Config config={}){
 SigDb db;
 if(!db.load(pathUtf8(dbPath)))return failure("Cannot open database: "+pathUtf8(dbPath));
 if(!db.warnings.empty())return failure(db.warnings.front());
 return std::make_unique<Scanner>(std::move(db),config);
}
}
