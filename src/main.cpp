#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <psapi.h>

bool isReadable(DWORD protect) {
    return (protect & PAGE_READONLY) ||
           (protect & PAGE_READWRITE) ||
           (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE);
}

enum class Command {
    EXIT,
    NEW,
    SHOW,
    WRITE,
    SCAN,
    INVALID
};

struct Process {
    std::string name;
    DWORD pid;
};

Command stringToCommand(const std::string& input) {
    if (input == "exit") return Command::EXIT;
    if (input == "new") return Command::NEW;
    if (input == "show") return Command::SHOW;
    if (input == "write") return Command::WRITE;
    
    // Check if input is a number
    try {
        (void)std::stoi(input); // Suppress unused variable warning
        return Command::SCAN;
    } catch (...) {
        return Command::INVALID;
    }
}

std::vector<Process> listProcesses() {
    std::vector<Process> processes;
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    DWORD cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return processes;
    }
    
    cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            char szProcessName[MAX_PATH] = "<unknown>";
            HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i] );

            if (NULL != hProcess ) {
                HMODULE hMod;
                DWORD cbNeededModules;

                if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeededModules) ) {
                    GetModuleBaseNameA( hProcess, hMod, szProcessName, sizeof(szProcessName)/sizeof(char) );
                }
            }

            std::string processName = std::string((const char*)szProcessName);

            if (processName.find("<unknown>") == std::string::npos) {
                processes.push_back({processName, aProcesses[i]});
            }
            CloseHandle( hProcess );
        }
    }
    return processes;
}

HANDLE getProcessHandle() {
    DWORD pid;
    HANDLE hProcess;

    while (true) {
        std::cout << "Enter PID of process to scan: ";
        std::cin >> pid;
        std::cin.ignore();

        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hProcess) {
            std::cerr << "Failed to open process." << std::endl;
            continue;
        }
        std::cout << "Process opened successfully." << std::endl;
        break;
    }
    return hProcess;
}

// Scans memory for addresses that contain specified value
std::vector<uintptr_t> scanMemoryForInt(HANDLE hProcess, int value) {
    std::vector<uintptr_t> foundAddresses;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPCVOID addr = sysInfo.lpMinimumApplicationAddress;
    while (addr < sysInfo.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && isReadable(mbi.Protect)) {
                std::vector<char> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i + sizeof(int) <= bytesRead; ++i) {
                        int* p = reinterpret_cast<int*>(&buffer[i]);
                        if (*p == value) {
                            uintptr_t foundAddr = (uintptr_t)mbi.BaseAddress + i;
                            foundAddresses.push_back(foundAddr);
                        }
                    }
                }
            }
            addr = (LPCVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
        } else {
            break;
        }
    }
    return foundAddresses;
}

// Filters addresses to only include those that contain specified value
std::vector<uintptr_t> filterAddressesByIntValue(HANDLE hProcess, const std::vector<uintptr_t>& addresses, int value) {
    std::vector<uintptr_t> newAddresses;
    for (auto address : addresses) {
        int memValue = 0;
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)address, &memValue, sizeof(int), &bytesRead)) {
            if (bytesRead == sizeof(int) && memValue == value) {
                newAddresses.push_back(address);
            }
        }
    }
    return newAddresses;
}

// Writes a value to an address
bool writeIntToAddress(HANDLE hProcess, uintptr_t address, int newValue) {
    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(hProcess, (LPVOID)address, &newValue, sizeof(int), &bytesWritten) && bytesWritten == sizeof(int);
}

int main() {

    std::vector<Process> processes = listProcesses();
    for (const auto& process : processes) {
        std::cout << process.name << " (PID: " << process.pid << ")" << std::endl;
    }

    HANDLE hProcess = getProcessHandle();

    std::vector<uintptr_t> foundAddresses;
    bool firstScan = true;
    std::string input;

    while (true) {
        std::cout << "\nEnter value to scan for (or 'show'/'write'/'new'/'exit'): ";
        std::getline(std::cin, input);

        switch (stringToCommand(input)) {
            case Command::EXIT:
                return 0;

            case Command::NEW:
                firstScan = true;
                break;

            case Command::SHOW: {
                std::cout << "Current addresses (" << foundAddresses.size() << "):\n";
                size_t idx = 0;
                for (const auto& addr : foundAddresses) {
                    std::cout << "[" << idx++ << "] - 0x" << std::hex << addr << std::dec << '\n';
                }
                break;
            }
            case Command::WRITE: {
                std::string addrInput, valueInput;
                std::cout << "Enter address to overwrite (hex, e.g. 0x1234abcd): ";
                std::getline(std::cin, addrInput);
                uintptr_t address = 0;
                std::istringstream addrStream(addrInput);
                addrStream >> std::hex >> address;
                if (!address) {
                    std::cout << "Invalid address." << std::endl;
                    break;
                }
                std::cout << "Enter new integer value: ";
                std::getline(std::cin, valueInput);
                int newValue = 0;
                std::istringstream valueStream(valueInput);
                if (!(valueStream >> newValue)) {
                    std::cout << "Invalid value." << std::endl;
                    break;
                }
                if (writeIntToAddress(hProcess, address, newValue)) {
                    std::cout << "Successfully wrote value " << newValue << " to address 0x" << std::hex << address << std::dec << std::endl;
                } else {
                    std::cout << "Failed to write value. (Try running as administrator or check permissions)" << std::endl;
                }
                break;
            }

            case Command::SCAN: {
                int value;
                std::istringstream iss(input);
                iss >> value; // We already know it's a number from stringToCommand
                
                if (firstScan) {
                    foundAddresses = scanMemoryForInt(hProcess, value);
                    firstScan = false;
                } else {
                    foundAddresses = filterAddressesByIntValue(hProcess, foundAddresses, value);
                }
                std::cout << "Found " << foundAddresses.size() << " matching addresses." << std::endl;
                break;
            }

            case Command::INVALID:
                std::cout << "Invalid command." << std::endl;
                break;
        }
    }

    CloseHandle(hProcess);
    return 0; //
}