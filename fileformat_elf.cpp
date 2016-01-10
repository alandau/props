#include "fileformat_elf.h"
#include "elf.h"
#include "optional.h"
#include <sstream>
#include <distorm.h>
#include <mnemonics.h>
#include <deque>
#include <set>

static std::string join(std::vector<std::string> v, std::string sep) {
    std::string res;
    auto it = v.begin();
    if (it != v.end()) {
        res = *it;
        ++it;
    }
    for (; it != v.end(); ++it) {
        res += sep;
        res += *it;
    }
    return res;
}

class ELFFileFormat::StrTab {
public:
    StrTab(const void* start, size_t len)
        : data_(static_cast<const char*>(start))
        , len_(len)
    {}

    std::string get(size_t offset) {
        return std::string(data_ + offset);
    }

private:
    const char* data_;
    size_t len_;
};

static std::string to_hexstring(uint64_t num) {
    std::ostringstream os;
    os << "0x" << std::hex << num;
    return os.str();
}

struct Item {
    unsigned index;
    const char* value;
};

class Table {
public:
    enum class Options {NONE, HEX};

    Table(Options options, std::initializer_list<Item> list)
        : options_(options)
    {
        int firstIndex = -1;
        if (list.size() != 0) {
            firstIndex = list.begin()->index;
        }
        items_.reserve(list.size());
        int lastIndex = firstIndex - 1;
        bool consecutive = true;
        for (const Item& item : list) {
            items_.push_back(item);
            if (item.index != lastIndex + 1) {
                consecutive = false;
            }
            lastIndex++;
        }
        if (consecutive) {
            firstIndex_ = firstIndex;
        }
    }

    Table(std::initializer_list<Item> list)
        : Table(Options::NONE, std::move(list))
    {}

    std::string get(unsigned index) const {
        if (firstIndex_ != -1) {
            // items are consecutive
            if (index >= firstIndex_ && index < firstIndex_ + items_.size()) {
                return items_[index - firstIndex_].value;
            } else {
                return getDefault(index);
            }
        }

        for (const Item& item : items_) {
            if (item.index == index) {
                return item.value;
            }
        }
        return getDefault(index);
    }
private:
    Options options_;
    std::vector<Item> items_;
    int firstIndex_ = -1;

    std::string getDefault(unsigned index) const {
        return "Unknown ("
                + (options_ == Options::HEX ? to_hexstring(index) : std::to_string(index))
                + ")";
    }
};

Table typeTable = {
    {ET_REL, "Object"},
    {ET_EXEC, "Executable"},
    {ET_DYN, "Shared object"},
    {ET_CORE, "Core file"},
};

Table classTable = {
    {ELFCLASS32, "32 bit"},
    {ELFCLASS64, "64 bit"},
};

Table machineTable = {
    {EM_NONE, "None"},
    {EM_386, "Intel 80386"},
    {EM_X86_64, "x86-64"},
};

Table segmentTypes = {Table::Options::HEX, {
    {PT_NULL, "NULL"},
    {PT_LOAD, "LOAD"},
    {PT_DYNAMIC, "DYNAMIC"},
    {PT_INTERP, "INTERP"},
    {PT_NOTE, "NOTE"},
    {PT_SHLIB, "SHLIB"},
    {PT_PHDR, "PHDR"},
    {PT_TLS, "TLS"},
    {PT_GNU_EH_FRAME, "GNU_EH_FRAME"},
    {PT_GNU_STACK, "GNU_STACK"},
    {PT_GNU_RELRO, "GNU_RELRO"},
}};

Table dynamicTable = {Table::Options::HEX, {
    {DT_NULL, "NULL"},
    {DT_NEEDED, "NEEDED"},
    {DT_PLTRELSZ, "PLTRELSZ"},
    {DT_PLTGOT, "PLTGOT"},
    {DT_HASH, "HASH"},
    {DT_STRTAB, "STRTAB"},
    {DT_SYMTAB, "SYMTAB"},
    {DT_RELA, "RELA"},
    {DT_RELASZ, "RELASZ"},
    {DT_RELAENT, "RELAENT"},
    {DT_STRSZ, "STRSZ"},
    {DT_SYMENT, "SYMENT"},
    {DT_INIT, "INIT"},
    {DT_FINI, "FINI"},
    {DT_SONAME, "SONAME"},
    {DT_RPATH, "RPATH"},
    {DT_SYMBOLIC, "SYMBOLIC"},
    {DT_REL, "REL"},
    {DT_RELSZ, "RELSZ"},
    {DT_RELENT, "RELENT"},
    {DT_PLTREL, "PLTREL"},
    {DT_DEBUG, "DEBUG"},
    {DT_TEXTREL, "TEXTREL"},
    {DT_JMPREL, "JMPREL"},
    {DT_BIND_NOW, "BIND_NOW"},
    {DT_INIT_ARRAY, "INIT_ARRAY"},
    {DT_FINI_ARRAY, "FINI_ARRAY"},
    {DT_INIT_ARRAYSZ, "INIT_ARRAYSZ"},
    {DT_FINI_ARRAYSZ, "FINI_ARRAYSZ"},
    {DT_RUNPATH, "RUNPATH"},
    {DT_FLAGS, "FLAGS"},
    {DT_ENCODING, "ENCODING"},
    {DT_PREINIT_ARRAY, "PREINIT_ARRAY"},
    {DT_PREINIT_ARRAYSZ, "PREINIT_ARRAYSZ"},
    {DT_GNU_HASH, "GNU_HASH"},
    {DT_VERSYM, "VERSYM"},
    {DT_VERNEED, "VERNEED"},
    {DT_VERNEEDNUM, "VERNEEDNUM"},
}};

static std::string flagsToStr(uint16_t flags) {
    std::string res;
    res += flags & PF_R ? "r" : "-";
    res += flags & PF_W ? "w" : "-";
    res += flags & PF_X ? "x" : "-";
    flags &= ~(PF_R | PF_W | PF_X);
    if (flags != 0) {
        res += " | " + to_hexstring(flags);
    }
    return res;
}

size_t ELFFileFormat::vaddrToOffset(const std::vector<SegmentInfo>& segments, size_t vaddr) {
    for (const SegmentInfo& seg : segments) {
        if (vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.memsz && vaddr - seg.vaddr < seg.filesz) {
            return seg.offset + (vaddr - seg.vaddr);
        }
    }
    return static_cast<size_t>(-1);
}

ELFFileFormat::ELFFileFormat(const void *data, size_t size)
    : FileFormat(data, size)
{
    const Elf64_Ehdr* hdr = static_cast<const Elf64_Ehdr*>(data_);

    metadata_.entryPoint = hdr->e_entry;

    metadata_.tables = {
        {"ELF Header", {"Header", "Value"}, {} },
        {"Program Header", {"Type", "Flags", "Vaddr", "MemSz", "Offset", "FileSz", "Extra"}, {}},
    };

    metadata_.tables[0].items.push_back({"Type", typeTable.get(hdr->e_type)});
    metadata_.tables[0].items.push_back({"Class", classTable.get(hdr->e_ident[EI_CLASS])});
    metadata_.tables[0].items.push_back({"Machine", machineTable.get(hdr->e_machine)});
    metadata_.tables[0].items.push_back({"Entry Point", to_hexstring(hdr->e_entry)});

    entry_ = hdr->e_entry;

    const Elf64_Phdr* dynamic = nullptr;

    for (unsigned i = 0; i < hdr->e_phnum; i++) {
        auto phdrEntry = static_cast<const Elf64_Phdr*>(data + hdr->e_phoff + i * hdr->e_phentsize);
        if (phdrEntry->p_type == PT_DYNAMIC) {
            dynamic = phdrEntry;
        }
        std::string extra;
        if (phdrEntry->p_type == PT_INTERP && phdrEntry->p_filesz < 1000) {
            extra = std::string(static_cast<const char*>(data + phdrEntry->p_offset), phdrEntry->p_filesz);
        }
        metadata_.tables[1].items.push_back({
            segmentTypes.get(phdrEntry->p_type),
            flagsToStr(phdrEntry->p_flags),
            to_hexstring(phdrEntry->p_vaddr),
            std::to_string(phdrEntry->p_memsz),
            to_hexstring(phdrEntry->p_offset),
            std::to_string(phdrEntry->p_filesz),
            extra,
        });
        if (phdrEntry->p_type == PT_LOAD) {
            segments_.push_back({phdrEntry->p_vaddr, phdrEntry->p_memsz, phdrEntry->p_offset, phdrEntry->p_filesz});
        }
    }

    if (dynamic) {
        size_t strtab = 0, strtabsize = 0;
        for (size_t offset = dynamic->p_offset; offset < dynamic->p_offset + dynamic->p_filesz; offset += sizeof(Elf64_Dyn)) {
            auto entry = static_cast<const Elf64_Dyn*>(data + offset);
            if (entry->d_tag == DT_STRTAB) {
                strtab = entry->d_un.d_val;
            } else if (entry->d_tag == DT_STRSZ) {
                strtabsize = entry->d_un.d_val;
            }
        }

        if (strtab != 0 && strtabsize != 0) {
            size_t offset = vaddrToOffset(segments_, strtab);
            if (offset != -1) {
                strtab_.reset(new StrTab(static_cast<const char*>(data + offset), strtabsize));
            }
        }

        FileFormat::Table table = {"Dynamic", {"Tag", "Value"}, {}};
        for (size_t offset = dynamic->p_offset; offset < dynamic->p_offset + dynamic->p_filesz; offset += sizeof(Elf64_Dyn)) {
            auto entry = static_cast<const Elf64_Dyn*>(data + offset);
            std::string value = entry->d_tag == DT_NEEDED && strtab_ ?
                        strtab_->get(entry->d_un.d_val) :
                        to_hexstring(entry->d_un.d_val);
            table.items.push_back({dynamicTable.get(entry->d_tag), std::move(value)});
        }
        metadata_.tables.push_back(std::move(table));
    }
}


FileFormat::Metadata ELFFileFormat::getMetadata() {
    return metadata_;
}

void ELFFileFormat::disassemble(ListingIface& listing, Symtab& symtab) {
    for (const auto seg : segments_) {
        listing.addSegment(seg.vaddr, seg.memsz, static_cast<const uint8_t*>(data_ + seg.offset), seg.filesz);
    }

    _CodeInfo ci = {0};

    size_t startOffset = vaddrToOffset(segments_, entry_);
    const size_t initialVaddr = segments_[0].vaddr;
    const size_t sz = segments_[0].filesz;

    std::deque<uint64_t> q;
    std::set<uint64_t> visited;

    while (true) {
        ci.code = static_cast<const uint8_t*>(data_ + startOffset);
        ci.codeLen = sz - startOffset;
        ci.codeOffset = initialVaddr + startOffset;
        ci.dt = Decode64Bits;
        ci.features = DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_UNC_BRANCH;
        _DInst inst[50];
        unsigned instCount = 0;
        _DecodeResult res = distorm_decompose(&ci, inst, 50, &instCount);
        if (res == DECRES_INPUTERR) {
            int x=5/0;
            return;
        }

        for (int i = 0; i < instCount; i++) {
            const _DInst& curInst = inst[i];
            _DecodedInst decoded;
            distorm_format(&ci, &curInst, &decoded);

            ListingIface::Data data;
            data.hex = reinterpret_cast<const char*>(decoded.instructionHex.p);
            {
                char one[100];
                sprintf(one, "%s%s%s", decoded.mnemonic.p, decoded.operands.length != 0 ? " " : "", decoded.operands.p);
                for (char* p = one; *p; p++) {
                    *p = tolower(*p);
                }
                data.instruction = one;
            }
            data.length = static_cast<uint8_t>(decoded.size);

            Optional<uint64_t> addrInInst;
            bool showAddr = false;
            for (int j = 0; j < OPERANDS_NO; j++) {
                const _Operand& op = curInst.ops[j];
                if (op.type == O_NONE) {
                    break;
                }
                if (op.type == O_SMEM && op.index == R_RIP) {
                    showAddr = true;
                    addrInInst = INSTRUCTION_GET_RIP_TARGET(&curInst);
                    break;
                }
                if (op.type == O_SMEM || op.type == O_MEM || op.type == O_DISP) {
                    addrInInst = curInst.disp;
                    break;
                }
                if (op.type == O_IMM) {
                    addrInInst = curInst.imm.qword;
                    break;
                }
            }

            int fc = META_GET_FC(curInst.meta);
            if (fc == FC_CALL || fc == FC_CND_BRANCH || fc == FC_UNC_BRANCH) {
                if (curInst.ops[0].type == O_PC) {
                    uint64_t to = INSTRUCTION_GET_TARGET(&curInst);
                    listing.addBranch(curInst.addr, to);
                    addrInInst = to;
                }
            }

            if (addrInInst) {
                if (showAddr) {
                    data.instructionComment = to_hexstring(addrInInst.get());
                }
                std::vector<std::string> syms = symtab.get(addrInInst.get());
                if (!syms.empty()) {
                    if (!data.instructionComment.empty()) {
                        data.instructionComment += ' ';
                    }
                    data.instructionComment += "<" + join(syms, "> <") + ">";
                }
            }
            listing.addAddress(decoded.offset, std::move(data));
            visited.insert(decoded.offset);
        }

        if (instCount == 0) {
            int y=1/0;
            return;
        }

        _DInst& lastInst = inst[instCount - 1];
        startOffset = lastInst.addr + lastInst.size - initialVaddr;

        if (res == DECRES_SUCCESS) {
            int fc = META_GET_FC(lastInst.meta);
            if (fc == FC_RET) {
                if (q.empty()) {
                    break; // All instructions were decoded.
                }
                startOffset = q.front() - initialVaddr;
                q.pop_front();
            } else {
                uint64_t targetAddr = INSTRUCTION_GET_TARGET(&lastInst);
                if (visited.find(targetAddr) == visited.end() && lastInst.ops[0].type == O_PC) {
                    visited.insert(targetAddr);
                    if (fc == FC_UNC_BRANCH) {
                        startOffset = targetAddr - initialVaddr;
                    } else if (fc == FC_CALL || fc == FC_CND_BRANCH) {
                        q.push_back(targetAddr);
                    }
                }
            }
        }
    }
//    listing.recalculate();
}
