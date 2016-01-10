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
