#pragma once

#include "fileformat.h"
#include <memory>

class ELFFileFormat : public FileFormat {
public:
    ELFFileFormat(const void* data, size_t len);
    Metadata getMetadata() override;
    void disassemble(ListingIface& listing, Symtab& symtab) override;
private:
    class StrTab;
    struct SegmentInfo {
        size_t vaddr;
        size_t memsz;
        size_t offset;
        size_t filesz;
    };

    Metadata metadata_;
    std::vector<SegmentInfo> segments_;
    std::unique_ptr<StrTab> strtab_;
    size_t entry_;

    static size_t vaddrToOffset(const std::vector<SegmentInfo>& segments, size_t vaddr);
};
