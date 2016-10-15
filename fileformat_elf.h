#pragma once

#include "fileformat.h"
#include "optional.h"
#include <memory>

class ELFFileFormat : public FileFormat {
public:
    ELFFileFormat(const void* data, size_t len);
    Metadata getMetadata() override;
    void disassemble(ListingIface& listing, Symtab& symtab) override;
    void loadSymbols(Symtab& symtab) override;
    void recalcCommentsAfterSymtabChange(ListingIface& listing, const Symtab& symtab) override;
    void findFeatures(ListingIface& listing, Symtab& symtab) override;
private:
    class StrTab;
    class Rela;
    class SymsSection;
    struct SegmentInfo {
        size_t vaddr;
        size_t memsz;
        size_t offset;
        size_t filesz;
    };

    Metadata metadata_;
    std::vector<SegmentInfo> segments_;
    std::unique_ptr<StrTab> strtab_;
    std::unique_ptr<Rela> rela_;
    std::unique_ptr<Rela> pltrela_;
    std::unique_ptr<SymsSection> symsSection_;
    size_t entry_;
    StringTab stringTab_;

    static size_t vaddrToOffset(const std::vector<SegmentInfo>& segments, size_t vaddr);

    void findStrings(ListingIface& listing, Symtab& symtab);
    Optional<std::pair<uint64_t, uint64_t>> findString(uint64_t start, uint64_t end);
    std::string generateSymbolForString(const std::pair<uint64_t, uint64_t>& range);
};
