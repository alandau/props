#include "listing.h"
#include <assert.h>

Listing::Listing(Symtab& symtab)
    : symtab_(symtab)
{

}

void Listing::addAddress(uint64_t address, Data&& data) {
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

void Listing::addBranch(uint64_t from, uint64_t to, bool conditional) {
    branches_[from] = {to, conditional};
    revbranches_.insert(std::make_pair(to, Branch{from, conditional}));
}

Optional<Listing::Branch> Listing::getBranchFrom(uint64_t from) const {
    auto it = branches_.find(from);
    return it == branches_.end() ? Optional<Branch>() : Optional<Branch>(it->second);
}

std::vector<Listing::Branch> Listing::getBranchesTo(uint64_t to) const {
    auto range = revbranches_.equal_range(to);
    std::vector<Branch> res;
    for (auto it = range.first; it != range.second; ++it) {
        res.push_back(it->second);
    }
    return res;
}

ListingIface::Data& Listing::getDataRef(uint64_t address) {
    auto it = listing_.find(address);
    assert(it != listing_.end());
    return it->second;
}

ListingIface::iterator Listing::begin() {
    return listing_.begin();
}

ListingIface::iterator Listing::end() {
    return listing_.end();
}
