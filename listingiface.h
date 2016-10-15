#ifndef LISTINGIFACE_H
#define LISTINGIFACE_H

#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <distorm.h>
#include "optional.h"

class ListingIface {
public:
    struct Data {
        std::vector<std::string> comments;
        std::string hex;
        std::string instruction;
        std::string instructionComment;
        uint8_t length;
        _DInst inst;
    };

    virtual void addSegment(uint64_t vaddr, uint64_t memsz, const uint8_t* data, uint64_t filesz) = 0;
    virtual void addAddress(uint64_t address, Data&& data) = 0;
    virtual void addBranch(uint64_t from, uint64_t to, bool conditional) = 0;
    virtual Data& getDataRef(uint64_t address) = 0;

    using iterator = std::map<uint64_t, Data>::iterator;
    virtual iterator begin() = 0;
    virtual iterator end() = 0;
};

class Symtab {
public:
    void insert(uint64_t addr, std::string sym) {
        auto r = tab_.equal_range(addr);
        auto f = std::find_if(r.first, r.second, [&sym](decltype(*r.first) v) {return v.second == sym;});
        if (f != r.second) {
            return;
        }
        tab_.insert(std::make_pair(addr, std::move(sym)));
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

class StringTab {
public:
    void insert(uint64_t addr, std::string str) {
        tab_.insert(std::make_pair(addr, std::move(str)));
    }
    Optional<std::string> get(uint64_t addr) const {
        auto it = tab_.find(addr);
        if (it == tab_.end()) {
            return Optional<>::absent;
        }
        return it->second;
    }
private:
    std::map<uint64_t, std::string> tab_;
};

#endif // LISTINGIFACE_H

