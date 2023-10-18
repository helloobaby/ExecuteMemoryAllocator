#pragma once
#include <Windows.h>

#include <algorithm>
#include <vector>
#include <string>
#include <cassert>
#include <map>

std::vector<std::string> kVictimDllName{"mfc140ud.dll"};


struct kVictimTextSectionInfo {
  void* Start;
  size_t Size;
};

std::vector<kVictimTextSectionInfo> kVictimInfo;

//Memory Allocator 
class ExecAllocator {
 public:
  ExecAllocator() = default;
  
  bool Init(bool OnlyTextSection = true);

  void* Malloc(size_t Size);

  size_t GetMaxAllocSize();

  void merge();

 protected:
 private:
};


// Core.Alloc.cpp
bool ExecAllocator::Init(bool OnlyTextSection) {
  bool ChangeProtection = false;
  for (const auto& name : kVictimDllName) {
    HMODULE hDll =
         LoadLibraryExA(name.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
        //LoadLibraryA(name.c_str());
    if (!hDll) continue;

    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hDll;
    IMAGE_NT_HEADERS32* NtHeader =
        (IMAGE_NT_HEADERS32*)((ULONGLONG)DosHeader + DosHeader->e_lfanew);
    auto TextSection = IMAGE_FIRST_SECTION(NtHeader);

    const int page_size = 0x1000; //4K
    const int _text_section_offset = page_size;
    
    
    if (OnlyTextSection) {
      kVictimInfo.push_back(
          {hDll + _text_section_offset, TextSection->SizeOfRawData});
      DWORD OldProtect;
      ChangeProtection = VirtualProtect(hDll + _text_section_offset,
                                     TextSection->SizeOfRawData,
                     PAGE_EXECUTE_READWRITE, &OldProtect);
    } else { // we need more continuous memory
      // add next section

       DWORD Sections = NtHeader->FileHeader.NumberOfSections;
      size_t Length = 0;
      for (UINT i = 0; i < Sections; i++) {
        Length += TextSection[i].SizeOfRawData;
      }
      DWORD OldProtect;
      ChangeProtection = VirtualProtect(hDll + _text_section_offset, Length,
                     PAGE_EXECUTE_READWRITE, &OldProtect);
      kVictimInfo.push_back({hDll + _text_section_offset, Length});
        
    }

    if (!ChangeProtection) return false;
  }

  return true;
}

void* ExecAllocator::Malloc(size_t Size) {
  auto iter = std::find_if(kVictimInfo.begin(), kVictimInfo.end(),
               [&](kVictimTextSectionInfo& t) {
                 if (t.Size >= Size)
                   return true;
                 else
                   return false;
               });

  if (iter != kVictimInfo.end()) {
    return iter->Start;
  }

    return nullptr; }


size_t ExecAllocator::GetMaxAllocSize() {
  if (!kVictimInfo.empty()) {
    return std::max_element(kVictimInfo.begin(), kVictimInfo.end(),
                            [](const kVictimTextSectionInfo& t1,
                               const kVictimTextSectionInfo& t2) {
                              return t1.Size < t2.Size;
                            })
        ->Size;
  } 

  return 0;
}


void ExecAllocator::merge() {

}