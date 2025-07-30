#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <psapi.h>
#include <variant>

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
    HELP,
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
    if (input.rfind("write ", 0) == 0) return Command::WRITE;
    if (input == "help") return Command::HELP;
    if (input.rfind("scan ", 0) == 0) return Command::SCAN;
    return Command::INVALID;
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

bool parseScanCommand(const std::string& input, std::string& type, std::variant<int, float>& value) {
    auto tokens = split(input, ' ');
    if (tokens.size() < 3) return false;
    
    if (tokens[0] != "scan") return false;
    if (tokens[1] != "int" && tokens[1] != "float") return false;
    
    type = tokens[1];
    
    try {
        if (type == "int") {
            value = std::stoi(tokens[2]);
            return true;
        } else if (type == "float") {
            value = std::stof(tokens[2]);
            return true;
        }
    } catch (const std::exception&) {
        return false;
    }
    
    return false;
}

bool parseWriteCommand(const std::string& input, std::string& type, uintptr_t& address, std::variant<int, float>& value) {
    auto tokens = split(input, ' ');
    if (tokens.size() < 4) return false;
    
    if (tokens[0] != "write") return false;
    if (tokens[1] != "int" && tokens[1] != "float") return false;
    
    type = tokens[1];
    
    try {
        // Parse address (hex format)
        address = std::stoull(tokens[2], nullptr, 16);
        
        // Parse value
        if (type == "int") {
            value = std::stoi(tokens[3]);
            return true;
        } else if (type == "float") {
            value = std::stof(tokens[3]);
            return true;
        }
    } catch (const std::exception&) {
        return false;
    }
    
    return false;
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
        std::cout << "\nEnter PID of process to scan: ";
        std::cin >> pid;
        std::cin.ignore();

        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hProcess) {
            std::cerr << "Failed to open process." << std::endl;
            std::cin.ignore();
            continue;
        }
            
        system("cls");
        break;
    }
    return hProcess;
}

// Scans memory for addresses that contain specified value
std::vector<uintptr_t> scanMemory(HANDLE hProcess, std::variant<int, float> value) {
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
                    if (std::holds_alternative<int>(value)) {
                        for (size_t i = 0; i + sizeof(int) <= bytesRead; ++i) {
                            int* p = reinterpret_cast<int*>(&buffer[i]);
                            if (*p == std::get<int>(value)) {
                            uintptr_t foundAddr = (uintptr_t)mbi.BaseAddress + i;
                            foundAddresses.push_back(foundAddr);
                            }
                        }
                    } else if (std::holds_alternative<float>(value)) {
                        for (size_t i = 0; i + sizeof(float) <= bytesRead; ++i) {
                            float* p = reinterpret_cast<float*>(&buffer[i]);
                            if (*p == std::get<float>(value)) {
                                uintptr_t foundAddr = (uintptr_t)mbi.BaseAddress + i;
                                foundAddresses.push_back(foundAddr);
                            }
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
std::vector<uintptr_t> filterAddressesByValue(HANDLE hProcess, const std::vector<uintptr_t>& addresses, std::variant<int, float> value) {
    std::vector<uintptr_t> newAddresses;
    for (auto address : addresses) {
        SIZE_T bytesRead = 0;
        if (std::holds_alternative<int>(value)) {
            int memValue = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, &memValue, sizeof(int), &bytesRead)) {
                if (bytesRead == sizeof(int) && memValue == std::get<int>(value)) {
                newAddresses.push_back(address);
                }
            }
        } else if (std::holds_alternative<float>(value)) {
            float memValue = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, &memValue, sizeof(float), &bytesRead)) {
                if (bytesRead == sizeof(float) && memValue == std::get<float>(value)) {
                    newAddresses.push_back(address);
                }
            }
        }
    }
    return newAddresses;
}

// Writes a value to an address
bool writeToAddress(HANDLE hProcess, uintptr_t address, std::variant<int, float> newValue) {
    SIZE_T bytesWritten = 0;
    if (std::holds_alternative<int>(newValue)) {
        return WriteProcessMemory(hProcess, (LPVOID)address, &std::get<int>(newValue), sizeof(int), &bytesWritten) && bytesWritten == sizeof(int);
    } else if (std::holds_alternative<float>(newValue)) {
        return WriteProcessMemory(hProcess, (LPVOID)address, &std::get<float>(newValue), sizeof(float), &bytesWritten) && bytesWritten == sizeof(float);
    }
    return false;
}

void printHelp() {

    std::cout << "\nAvailable commands:\n"
              << "  scan <type> <value>             - Search for values in memory\n"
              << "  show                            - Display found addresses\n"
              << "  write <type> <address> <value>  - Write value to address\n"
              << "  new                             - Start a new scan\n"
              << "  help                            - Show this help message\n"
              << "  exit                            - Exit program\n";
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

    printHelp();

    while (true) {
        std::cout << "\n> ";
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
                std::string type;
                uintptr_t address;
                std::variant<int, float> value;
                
                if (!parseWriteCommand(input, type, address, value)) {
                    std::cout << "Usage: write <type> <address> <value>" << std::endl;
                    break;
                }

                if (type == "int") {
                    if (writeToAddress(hProcess, address, value)) {
                        std::cout << "Successfully wrote value " << std::get<int>(value) << " to address 0x" << std::hex << address << std::dec << std::endl;
                    } else {
                        std::cout << "Failed to write value. (Try running as administrator or check permissions)" << std::endl;
                    }
                } else if (type == "float") {
                    if (writeToAddress(hProcess, address, value)) {
                        std::cout << "Successfully wrote value " << std::get<float>(value) << " to address 0x" << std::hex << address << std::dec << std::endl;
                    } else {
                        std::cout << "Failed to write value. (Try running as administrator or check permissions)" << std::endl;
                    }
                } else {
                    std::cout << "Invalid type. Type 'help' for available commands." << std::endl;
                }

                break;
            }

            case Command::SCAN: {
                std::string type;
                std::variant<int, float> value;
                
                if (!parseScanCommand(input, type, value)) {
                    std::cout << "Usage: scan int <value> or scan float <value>" << std::endl;
                    break;
                }
                
                if (type == "int") {
                    if (firstScan) {
                        foundAddresses = scanMemory(hProcess, std::get<int>(value));
                        firstScan = false;
                    } else {
                        foundAddresses = filterAddressesByValue(hProcess, foundAddresses, std::get<int>(value));
                    }
                    std::cout << "Found " << foundAddresses.size() << " matching addresses." << std::endl;
                } else if (type == "float") {
                    if (firstScan) {
                        foundAddresses = scanMemory(hProcess, std::get<float>(value));
                        firstScan = false;
                    } else {
                        foundAddresses = filterAddressesByValue(hProcess, foundAddresses, std::get<float>(value));
                    }
                    std::cout << "Found " << foundAddresses.size() << " matching addresses." << std::endl;
                } else {
                    std::cout << "Only 'int' and 'float' types are supported currently." << std::endl;
                }
                break;
            }

            case Command::HELP:
                printHelp();
                break;

            case Command::INVALID:
                std::cout << "Invalid command. Type 'help' for available commands." << std::endl;
                break;
        }
    }

    CloseHandle(hProcess);
    return 0; //
}