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

    Listing(Symtab& symtab);
    void addAddress(uint64_t address, Data&& data) override;
    void addSegment(uint64_t vaddr, uint64_t memsz, const uint8_t* data, uint64_t filesz) override;
    void recalculate() override;
    void addBranch(uint64_t from, uint64_t to) override;
    std::pair<uint64_t,uint32_t> rowToAddress(size_t row) const;
    size_t size() const;
    Data getData(uint64_t address) const;
    const std::vector<Segment>& getSegments() const;
    Optional<uint64_t> getBranch(uint64_t from) const;
private:
    std::vector<Segment> segments_;
    std::map<uint64_t, Data> listing_;
    std::map<uint32_t, std::pair<uint64_t, size_t>> rowToAddress_;
    std::map<uint64_t, uint64_t> branches_;
    std::map<uint64_t, uint64_t> revbranches_;
    Symtab& symtab_;
};

#endif // LISTING_H
