#ifndef LISTINGIFACE_H
#define LISTINGIFACE_H

#include <vector>
#include <string>
#include <map>

class ListingIface {
public:
    struct Data {
        std::vector<std::string> comments;
        std::string hex;
        std::string instruction;
        std::string instructionComment;
        uint32_t row;
        uint8_t length;
    };

    virtual void addSegment(uint64_t vaddr, uint64_t memsz, const uint8_t* data, uint64_t filesz) = 0;
    virtual void addAddress(uint64_t address, Data&& data) = 0;
    virtual void addBranch(uint64_t from, uint64_t to) = 0;
    virtual void recalculate() = 0;
};

class Symtab {
public:
    Symtab() {
        tab_.insert(std::make_pair(0x401400, "entry"));
        tab_.insert(std::make_pair(0x401400, "entry2"));
        tab_.insert(std::make_pair(0x4011a0, "__libc_start_main@plt"));
        tab_.insert(std::make_pair(0x606228, "stdout"));
        tab_.insert(std::make_pair(0x403da4, "hahasym"));
    }
    size_t count(uint64_t addr) const {
        return tab_.count(addr);
    }
    std::vector<std::string> get(uint64_t addr) const {
        std::vector<std::string> res;
        auto range = tab_.equal_range(addr);
        for (auto it = range.first;  it != range.second; ++it) {
            res.push_back(it->second);
        }
        return res;
    }
private:
    std::multimap<uint64_t, std::string> tab_;
};

#endif // LISTINGIFACE_H

