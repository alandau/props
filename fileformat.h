#pragma once

#include "listingiface.h"
#include <vector>
#include <string>

class FileFormat {
public:
    struct Table {
        std::string name;
        std::vector<std::string> headers;
        std::vector<std::vector<std::string>> items;
    };

    struct Metadata {
        std::vector<Table> tables;
        uint64_t entryPoint;
    };

    FileFormat(const void *data, size_t size)
        : data_(data), size_(size)
    {}

    virtual Metadata getMetadata() = 0;
    virtual void disassemble(ListingIface& listing, Symtab& symtab) = 0;

protected:
    const void* data_;
    size_t size_;
};
