#ifndef LISTING_H
#define LISTING_H

#include "listingiface.h"
#include <assert.h>
#include <map>
#include "optional.h"

class Listing : public ListingIface
{
public:
    struct Segment {
        uint64_t vaddr;
        uint64_t memsz;
        std::vector<uint8_t> data;

        size_t addrToOffset(uint64_t addr) const {
            assert(addr >= vaddr);
            assert(addr < vaddr + memsz);
            return addr - vaddr;
        }
    };

    struct Branch {
        uint64_t addr;
        bool conditional;
    };

    Listing(Symtab& symtab);
    void addAddress(uint64_t address, Data&& data) override;
    void addSegment(uint64_t vaddr, uint64_t memsz, const uint8_t* data, uint64_t filesz) override;
    void addBranch(uint64_t from, uint64_t to, bool conditional) override;
    Data getData(uint64_t address) const;
    Data& getDataRef(uint64_t address) override;
    const std::vector<Segment>& getSegments() const;
    Optional<Branch> getBranchFrom(uint64_t from) const;
    std::vector<Branch> getBranchesTo(uint64_t to) const;
    iterator begin() override;
    iterator end() override;
private:
    std::vector<Segment> segments_;
    std::map<uint64_t, Data> listing_;
    std::map<uint64_t, Branch> branches_;
    std::multimap<uint64_t, Branch> revbranches_;
    Symtab& symtab_;
};

#endif // LISTING_H
