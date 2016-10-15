#include "fileformat_elf.h"
#include "elf.h"
#include <sstream>
#include <distorm.h>
#include <mnemonics.h>
#include <deque>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <cstring>

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

    std::string get(size_t offset) const {
        return std::string(data_ + offset);
    }

    size_t size() const {
        return len_;
    }

private:
    const char* data_;
    size_t len_;
};

class ELFFileFormat::Rela {
public:
    Rela(const void* start, size_t len, size_t entrySize)
        : data_(static_cast<const char*>(start))
        , len_(len)
        , entrySize_(entrySize)
    {}

    std::pair<uint64_t, uint32_t> get(size_t index) const {
        auto rela = reinterpret_cast<const Elf64_Rela*>(data_ + index * entrySize_);
        return {rela->r_offset, ELF64_R_SYM(rela->r_info)};
    }

    size_t size() const {
        return len_ / entrySize_;
    }

private:
    const char* data_;
    size_t len_;
    size_t entrySize_;
};

class ELFFileFormat::SymsSection {
public:
    SymsSection(const void* start, size_t len, size_t entrySize)
        : data_(static_cast<const char*>(start))
        , len_(len)
        , entrySize_(entrySize)
    {}

    uint64_t get(size_t index) const {
        auto sym = reinterpret_cast<const Elf64_Sym*>(data_ + index * entrySize_);
        return sym->st_name;
    }

    const Elf64_Sym* getSym(size_t index) const {
        return reinterpret_cast<const Elf64_Sym*>(data_ + index * entrySize_);
    }

    size_t size() const {
        return len_ / entrySize_;
    }
private:
    const char* data_;
    size_t len_;
    size_t entrySize_;
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
        std::unordered_map<size_t, size_t> dyn;
        for (size_t offset = dynamic->p_offset; offset < dynamic->p_offset + dynamic->p_filesz; offset += sizeof(Elf64_Dyn)) {
            auto entry = static_cast<const Elf64_Dyn*>(data + offset);
            switch (entry->d_tag) {
            case DT_STRTAB: case DT_STRSZ:
            case DT_RELA: case DT_RELASZ: case DT_RELAENT:
            case DT_SYMTAB: case DT_SYMENT:
            case DT_JMPREL: case DT_PLTRELSZ:
                dyn[entry->d_tag] = entry->d_un.d_val;
            }
        }

        if (dyn.find(DT_STRTAB) != dyn.end() && dyn.find(DT_STRSZ) != dyn.end()) {
            size_t offset = vaddrToOffset(segments_, dyn[DT_STRTAB]);
            if (offset != -1) {
                strtab_.reset(new StrTab(static_cast<const char*>(data + offset), dyn[DT_STRSZ]));
            }
        }

        if (dyn.find(DT_RELA) != dyn.end() && dyn.find(DT_RELASZ) != dyn.end()) {
            size_t offset = vaddrToOffset(segments_, dyn[DT_RELA]);
            if (offset != -1) {
                size_t entSize = dyn.find(DT_RELAENT) != dyn.end() ? dyn[DT_RELAENT] : sizeof(Elf64_Rela);
                rela_.reset(new Rela(static_cast<const char*>(data + offset), dyn[DT_RELASZ], entSize));
            }
        }

        if (dyn.find(DT_JMPREL) != dyn.end() && dyn.find(DT_PLTRELSZ) != dyn.end()) {
            size_t offset = vaddrToOffset(segments_, dyn[DT_JMPREL]);
            if (offset != -1) {
                size_t entSize = dyn.find(DT_RELAENT) != dyn.end() ? dyn[DT_RELAENT] : sizeof(Elf64_Rela);
                pltrela_.reset(new Rela(static_cast<const char*>(data + offset), dyn[DT_PLTRELSZ], entSize));
            }
        }

        if (dyn.find(DT_SYMTAB) != dyn.end()) {
            size_t offset = vaddrToOffset(segments_, dyn[DT_SYMTAB]);
            if (offset != -1) {
                size_t entSize = dyn.find(DT_SYMENT) != dyn.end() ? dyn[DT_SYMENT] : sizeof(Elf64_Sym);
                symsSection_.reset(new SymsSection(static_cast<const char*>(data + offset), size - offset, entSize));
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
            abort();
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
            data.inst = curInst;

#if 0
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
#endif
            int fc = META_GET_FC(curInst.meta);
            if (fc == FC_CALL || fc == FC_CND_BRANCH || fc == FC_UNC_BRANCH) {
                if (curInst.ops[0].type == O_PC) {
                    uint64_t to = INSTRUCTION_GET_TARGET(&curInst);
                    //addrInInst = to;
                    if (fc != FC_CALL) {
                        listing.addBranch(curInst.addr, to, fc == FC_CND_BRANCH);
                    }

                }
            }

            if (curInst.opcode == I_JMP && curInst.ops[0].type == O_SMEM && curInst.ops[0].index == R_RIP) {
                // Create PLT symbol
                uint64_t gotAddr = INSTRUCTION_GET_RIP_TARGET(&curInst);
                std::vector<std::string> syms = symtab.get(gotAddr);
                auto gotSymIter = std::find_if(syms.begin(), syms.end(), [](const std::string& sym){
                    return sym.size() >= 4 && sym.compare(sym.size() - 4, 4, "@got") == 0;
                });
                if (gotSymIter != syms.end()) {
                    std::string pltSym = std::string(*gotSymIter, 0, gotSymIter->size() - 4) + "@plt";
                    symtab.insert(curInst.addr, pltSym);
                }
            }

#if 0
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
#endif
            listing.addAddress(decoded.offset, std::move(data));
            visited.insert(decoded.offset);
        }

        if (instCount == 0) {
            abort();
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
                if (targetAddr >= initialVaddr && targetAddr < initialVaddr + sz &&
                        visited.find(targetAddr) == visited.end() && lastInst.ops[0].type == O_PC) {
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
}

void ELFFileFormat::loadSymbols(Symtab& symtab) {
    if (!symsSection_ || !strtab_) {
        return;
    }

    if (rela_) {
        // Dynamic entry RELA (aka .rela.dyn)
        for (size_t i = 0; i < rela_->size(); i++) {
            uint64_t address;
            uint32_t symIndex;
            std::tie(address, symIndex) = rela_->get(i);
            uint64_t strOffset = symsSection_->get(symIndex);
            std::string symbol = strtab_->get(strOffset);

            symtab.insert(address, symbol);
        }
    }

    if (pltrela_) {
        // Dynamic entry JMPREL (aka .rela.plt)
        for (size_t i = 0; i < pltrela_->size(); i++) {
            uint64_t address;
            uint32_t symIndex;
            std::tie(address, symIndex) = pltrela_->get(i);
            uint64_t strOffset = symsSection_->get(symIndex);
            std::string symbol = strtab_->get(strOffset) + "@got";

            symtab.insert(address, symbol);
        }
    }

    for (size_t i = 0; i < symsSection_->size(); i++) {
        const Elf64_Sym* sym = symsSection_->getSym(i);
        if (ELF64_ST_BIND(sym->st_info) > STB_WEAK ||
                ELF64_ST_TYPE(sym->st_info) > STT_COMMON ||
                sym->st_other > STV_PROTECTED ||
                sym->st_name > strtab_->size()) {
            break;
        }
        if (sym->st_value == 0) {
            continue;
        }
        std::string symbol = strtab_->get(sym->st_name);

        symtab.insert(sym->st_value, symbol);
    }
}

void ELFFileFormat::recalcCommentsAfterSymtabChange(ListingIface& listing, const Symtab& symtab) {
    for (auto& pair : listing) {
        auto& data = pair.second;
        const _DInst& curInst = data.inst;
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
            if (op.type == O_PC) {
                addrInInst = INSTRUCTION_GET_TARGET(&curInst);
                break;
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
            if (auto str = stringTab_.get(addrInInst.get())) {
                if (!data.instructionComment.empty()) {
                    data.instructionComment += ' ';
                }
                data.instructionComment += "\"" + *str + "\"";
            }
        }
    }
}

std::string ELFFileFormat::generateSymbolForString(const std::pair<uint64_t, uint64_t>& range) {
    std::string res;

    for (int i = range.first; i < range.second; i++) {
        char c = *(static_cast<const char*>(data_) + i);
        if ((c >= 'a' && c <= 'z') || (c >='A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
            res += c;
            if (res.size() >= 15) {
                break;
            }
        }
    }

    return "str_" + res;
}

Optional<std::pair<uint64_t, uint64_t>> ELFFileFormat::findString(uint64_t start, uint64_t end) {
    auto isStrChar = [](char c) {
      return (c >= 'a' && c <= 'z') || (c >='A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              (c != '\0' && std::strchr("_-!@#$%^&*()[]{}/\\:;.,<>|?`~ \r\n\t", c) != nullptr);
    };
    constexpr int kMinLen = 4;

    const char* p = static_cast<const char*>(data_);
    for (uint64_t i = start; i < end; i++) {
        if (!isStrChar(p[i])) {
            continue;
        }
        uint64_t j;
        for (j = i + 1; j < end; j++) {
            if (!isStrChar(p[j])) {
                break;
            }
        }
        if (j - i >= kMinLen) {
            return std::make_pair(i, j);
        }
        i = j;
    }
    return Optional<>::absent;
}

void ELFFileFormat::findStrings(ListingIface& listing, Symtab& symtab) {
    for (const SegmentInfo& seg : segments_) {
        uint64_t start = seg.offset;
        uint64_t end = seg.offset + seg.filesz;
        while (start < end) {
            auto str = findString(start, end);
            if (!str) {
                break;
            }
            uint64_t addr = seg.vaddr + (str->first - seg.offset);
            std::string string = generateSymbolForString(*str);
            symtab.insert(addr, string);
            stringTab_.insert(addr, std::string(static_cast<const char*>(data_) + str->first, str->second - str->first));
            start = str->second;
        }
    }
}

void ELFFileFormat::findFeatures(ListingIface& listing, Symtab& symtab) {
    auto iter = std::find_if(listing.begin(), listing.end(), [&symtab](const std::pair<uint64_t, ListingIface::Data>& p) {
        const _DInst& inst = p.second.inst;
        if (inst.opcode == I_CALL && inst.ops[0].type == O_PC) {
            std::vector<std::string> syms = symtab.get(INSTRUCTION_GET_TARGET(&inst));
            return std::find(syms.begin(), syms.end(), "__libc_start_main@plt") != syms.end();
        }
        return false;
    });

    if (iter == listing.end()) {
        return;
    }

    Optional<uint64_t> mainAddr;
    for (auto dist = 0; dist < 10 && iter != listing.begin(); dist++, --iter) {
        const _DInst& inst = iter->second.inst;
        if (inst.opcode == I_MOV && inst.ops[0].type == O_REG && inst.ops[0].index == R_RDI && inst.ops[1].type == O_IMM) {
            mainAddr = inst.ops[1].size == 32 ? inst.imm.dword : inst.imm.qword;
            break;
        }
    }

    if (mainAddr) {
        symtab.insert(mainAddr.get(), "main");
    }

    findStrings(listing, symtab);
}
