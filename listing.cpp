#include "listing.h"
#include <assert.h>

Listing::Listing(Symtab& symtab)
    : symtab_(symtab)
{

}

void Listing::addAddress(uint64_t address, Data&& data) {
    if (address == 0x401400) {
        data.instructionComment = "haha";
        data.comments = {"line 1", "line 2"};
    }
    listing_.insert(std::make_pair(address, std::move(data)));
}

void Listing::addSegment(uint64_t vaddr, uint64_t memsz, const uint8_t* data, uint64_t filesz) {
    segments_.push_back({vaddr, memsz, std::vector<uint8_t>(data, data + filesz)});
}

void Listing::recalculate() {
    rowToAddress_.clear();
    if (listing_.empty()) {
        return;
    }

    uint32_t row = 0;
    auto it = listing_.begin();
    uint64_t addr = it->first;

    while (it != listing_.end()) {
        if (addr == it->first) {
            it->second.row = row;
            size_t syms = symtab_.count(addr);
            for (size_t i = 0; i < it->second.comments.size() + syms; i++) {
                rowToAddress_[row] = std::make_pair(addr, i + 1);
                row++;
            }
            rowToAddress_[row] = std::make_pair(addr, 0);
            row++;
            addr += it->second.length;
            ++it;
        } else {
            rowToAddress_[row] = std::make_pair(addr, 0);
            row++;
            addr++;
        }
    }
}

std::pair<uint64_t,uint32_t> Listing::rowToAddress(size_t row) const {
#if 0
    size_t count = std::min<size_t>(listing_.size(), row);
    auto it = std::next(listing_.cbegin(), count);
    uint64_t addr = it == listing_.end() ? listing_.cend().->first + it->first;
    row -= count;
    if (row > 0) {
        addr += row;
    }
    return addr;
#endif
#if 0
    uint64_t addr = listing_.cbegin()->first;
    for (size_t i = 0; i < row; i++) {
        auto it = listing_.find(addr);
        if (it != listing_.cend()) {
            addr += it->second.length;
        } else {
            addr++;
        }
    }
    return addr;
#endif
    auto it = rowToAddress_.find(row);
    assert(it != rowToAddress_.end());
    return it->second;
}

size_t Listing::size() const {
    return rowToAddress_.size();
}

Listing::Data Listing::getData(uint64_t address) const {
    auto it = listing_.find(address);
    if (it != listing_.end()) {
        return it->second;
    } else {
        Data data;
        //data.hex = "??";
        //data.instruction = "??";
        data.length = 0;    // invalid
        return data;
    }
}

const std::vector<Listing::Segment>& Listing::getSegments() const {
    return segments_;
}

void Listing::addBranch(uint64_t from, uint64_t to) {
    branches_[from] = to;
    revbranches_[to] = from;
}

Optional<uint64_t> Listing::getBranch(uint64_t from) const {
    auto it = branches_.find(from);
    return it == branches_.end() ? Optional<uint64_t>() : Optional<uint64_t>(it->second);
}
