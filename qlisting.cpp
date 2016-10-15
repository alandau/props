#include "qlisting.h"
#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QMessageBox>
#include <QDebug>
#include <tuple>

QListing::QListing(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    setFont(QFont("Monospace"));
}

QListing::~QListing()
{
}

QListing::LineInfo::LineInfo() {

}

QListing::LineInfo::~LineInfo() {
}

void QListing::setData(const Listing* listing, const Symtab* symtab) {
    listing_ = listing;
    symtab_ = symtab;
    segment_ = &listing->getSegments()[0];
    calculate();
    adjust();
}

void QListing::drawRefline(QPainter& painter, int from, int to, int indent, int x, QColor color, bool conditional) {
    int start = pxCharHeight_ - fontMetrics().ascent();
    auto rowToY = [&](int row) { return start + row * pxCharHeight_ + pxCharHeight_ / 2; };

    int right = x - pxCharWidth_;
    int left = x - (indent + 4) * pxCharWidth_;
    int top = rowToY(from);
    int bottom = rowToY(to);
    int arrowHeight = pxCharHeight_ / 4;
    int arrowLength = pxCharWidth_;

    painter.setPen(QPen(color, 1, conditional ? Qt::DashLine : Qt::SolidLine));
    painter.drawLine(left, top, right, top);
    painter.drawLine(left, top, left, bottom);
    painter.drawLine(left, bottom, right, bottom);

    painter.setPen(color);
    painter.drawLine(right - arrowLength, bottom - arrowHeight, right, bottom);
    painter.drawLine(right - arrowLength, bottom + arrowHeight + 1, right, bottom + 1);
}

void QListing::drawArrow(QPainter& painter, int row, int x, Qt::ArrowType arrowType) {
    int start = pxCharHeight_ - fontMetrics().ascent();
    int right = x - pxCharWidth_;
    int y = start + row * pxCharHeight_ + pxCharHeight_ / 2;

    painter.setPen(arrowColors_[0]);

    switch (arrowType) {
    case Qt::RightArrow: {
        int arrowHeight = pxCharHeight_ / 4;
        int arrowLength = pxCharWidth_;
        painter.drawLine(right - arrowLength, y - arrowHeight, right, y);
        painter.drawLine(right - arrowLength, y + arrowHeight + 1, right, y + 1);
        break;
    }
    case Qt::UpArrow: {
        int arrowHalfWidth = pxCharWidth_ / 3;
        int arrowHeight = pxCharHeight_ / 3;
        int top = y - arrowHeight / 2;
        int bottom = y + arrowHeight / 2;
        painter.drawLine(right - 2 * arrowHalfWidth, bottom, right - arrowHalfWidth, top);
        painter.drawLine(right - arrowHalfWidth, top, right, bottom);
        break;
    }
    case Qt::DownArrow: {
        int arrowHalfWidth = pxCharWidth_ / 3;
        int arrowHeight = pxCharHeight_ / 3;
        int top = y - arrowHeight / 2;
        int bottom = y + arrowHeight / 2;
        painter.drawLine(right - 2 * arrowHalfWidth, top, right - arrowHalfWidth, bottom);
        painter.drawLine(right - arrowHalfWidth, bottom, right, top);
        break;
    }
    default:
        assert(false);
    }
}

uint32_t colorHash(uint32_t x) {
    x = ((x >> 16) ^ x) * 0x85ebca6b;
    x = ((x >> 13) ^ x) * 0xc2b2ae35;
    x = ((x >> 16) ^ x);
    return x;
}

void QListing::paintEvent(QPaintEvent* /*event*/) {
    if (listing_ == nullptr) {
        return;
    }
    QPainter painter(viewport());
    painter.fillRect(0, 0, pxAddrWidth_ + pxCharWidth_ / 2, viewport()->height(), palette().window().color());

    int hexWidthInChars = 20;

    int hexLeft = pxAddrWidth_ + pxCharWidth_;
    int hexWidth = hexWidthInChars * pxCharWidth_;
    int arrowsLeft = hexLeft + hexWidth;
    int arrowsWidth = 5 * pxCharWidth_;
    int labelLeft = arrowsLeft + arrowsWidth;
    int instLeft = labelLeft + 3 * pxCharWidth_;

    int y = pxCharHeight_;  // not 0 because drawText uses y as the font baseline position

    int firstRow = verticalScrollBar()->value();
    for (int i = firstRow; i < firstRow + numRows_; i++) {
        const LineInfo& info = lines_[i];
        switch (info.type) {
        case LineInfo::Type::INSTRUCTION: {
            painter.setPen(regularColor_);
            painter.drawText(0, y, QString::number(info.d.i.address, 16));
            painter.drawText(hexLeft, y, info.d.i.hex.mid(0, hexWidthInChars));
            painter.drawText(instLeft, y, info.d.i.instruction);
            if (!info.d.i.comment.isEmpty()) {
                painter.setPen(commentColor_);
                painter.drawText(instLeft + info.d.i.instruction.size() * pxCharWidth_, y, " ; " + info.d.i.comment);
            }
            break;
        }
        case LineInfo::Type::LABEL:
            painter.setPen(labelColor_);
            painter.drawText(labelLeft, y, info.d.l.label + ":");
            break;
        case LineInfo::Type::COMMENT:
            painter.setPen(commentColor_);
            painter.drawText(instLeft, y, "; " + info.d.c.comment);
            break;
        }
        y += pxCharHeight_;
    }


    struct Jump {
        uint64_t from;
        uint64_t to;
        bool conditional;
    };
    std::vector<Jump> jumps;

    for (int i = std::max(firstRow - 2 * numRows_, 0); i < firstRow + 3 * numRows_; i++) {
        const LineInfo& info = lines_[i];
        if (info.type != LineInfo::Type::INSTRUCTION) {
            continue;
        }

        if (Optional<Listing::Branch> branchTo = listing_->getBranchFrom(info.d.i.address)) {
            jumps.push_back({info.d.i.address, branchTo.get().addr, branchTo.get().conditional});
        }
        std::vector<Listing::Branch> branchesFrom = listing_->getBranchesTo(info.d.i.address);
        for (Listing::Branch from : branchesFrom) {
            jumps.push_back({from.addr, info.d.i.address, from.conditional});
        }
    }

    std::sort(jumps.begin(), jumps.end(), [](const Jump& a, const Jump& b) {
        // sort by to in increasing order, then by from in decreasing order
        Jump A = {std::min(a.from, a.to), std::max(a.from, a.to)};
        Jump B = {std::min(b.from, b.to), std::max(b.from, b.to)};
        if (A.to < B.to) {
            return true;
        } else if (A.to == B.to && A.from > B.from) {
            return true;
        }
        return false;
    });
    jumps.erase(std::unique(jumps.begin(), jumps.end(), [](const Jump& a, const Jump& b) {
        return a.from == b.from && a.to == b.to;
    }), jumps.end());

    std::vector<int> indents;
    for (const Jump& jump : jumps) {
        int from = addrToLine_.find(jump.from)->second.second;
        int to = addrToLine_.find(jump.to)->second.second;
        if (from >= firstRow - 2 * numRows_ && from < firstRow + 3 * numRows_ &&
                to >= firstRow - 2 * numRows_ && to < firstRow + 3 * numRows_) {
            int max = std::max(from, to);
            int min = std::min(from, to);
            auto it = std::find_if(indents.begin(), indents.end(), [min](int addr) {return addr < min;});
            int indent;
            if (it == indents.end()) {
                indents.push_back(max);
                indent = indents.size() - 1;
            } else {
                *it = max;
                indent = it - indents.begin();
            }
            drawRefline(painter, from - firstRow, to - firstRow, indent, instLeft, arrowColors_[colorHash(from) % arrowColors_.size()], jump.conditional);
        } else if (from >= firstRow && from < firstRow + numRows_) {
            drawArrow(painter, from - firstRow, instLeft, to > from ? Qt::DownArrow : Qt::UpArrow);
        } else if (to >= firstRow && to < firstRow + numRows_) {
            drawArrow(painter, to - firstRow, instLeft, Qt::RightArrow);
        }
    }
}

void QListing::resizeEvent(QResizeEvent* /*event*/) {
    adjust();
}

void QListing::mouseDoubleClickEvent(QMouseEvent* event) {
    if (event->button() != Qt::LeftButton) {
        QAbstractScrollArea::mouseDoubleClickEvent(event);
        return;
    }
    int y = (event->y() - fontMetrics().descent()) / pxCharHeight_;
    const LineInfo& info = lines_[verticalScrollBar()->value() + y];
    if (info.type != LineInfo::Type::INSTRUCTION) {
        return;
    }
    if (Optional<Listing::Branch> to = listing_->getBranchFrom(info.d.i.address)) {
        scrollToAddress(to.get().addr);
    }
}

void QListing::adjust() {
    numRows_ = (viewport()->height() + pxCharHeight_ - 1) / pxCharHeight_;
    if (numRows_ > lines_.size()) {
         numRows_ = lines_.size();
    }
    verticalScrollBar()->setRange(0, lines_.size() - numRows_);
    verticalScrollBar()->setPageStep(numRows_);
}

void QListing::setFont(const QFont& fnt) {
    QFont font = fnt;
    font.setStyleStrategy(QFont::ForceIntegerMetrics);
    QAbstractScrollArea::setFont(font);
    pxCharWidth_ = fontMetrics().width(QLatin1Char('5'));
    pxCharHeight_ = fontMetrics().height();
    viewport()->update();
}

void QListing::calculate() {
    lines_.clear();
    addrToLine_.clear();
    uint64_t addr = segment_->vaddr;
    while (addr < segment_->vaddr + segment_->memsz) {
        addrToLine_[addr].first = lines_.size();
        ListingIface::Data data = listing_->getData(addr);
        if (data.length == 0) {
            // no instruction at this address, treat as data
            size_t offset = segment_->addrToOffset(addr);
            uint8_t byte = offset < segment_->data.size() ? segment_->data[offset] : 0;
            std::string hex = QString("%1").arg(byte, 2, 16, QLatin1Char('0')).toStdString();
            lines_.push_back(LineInfo::instruction(addr, hex, "db 0x" + hex, ""));
            addrToLine_[addr].second = lines_.size();
            addr++;
            continue;
        }

        for (const std::string& comment : data.comments) {
            lines_.push_back(LineInfo::comment(comment));
        }

        for (const std::string& label : symtab_->get(addr)) {
            lines_.push_back(LineInfo::label(label));
        }

        addrToLine_[addr].second = lines_.size();
        lines_.push_back(LineInfo::instruction(addr, data.hex, data.instruction, data.instructionComment));

        addr += data.length;
    }

    uint64_t lastAddr = segment_->vaddr + segment_->memsz - 1;
    pxAddrWidth_ = QString::number(lastAddr, 16).length() * pxCharWidth_;
}

void QListing::scrollToAddress(uint64_t address) {
    auto it = addrToLine_.upper_bound(address);
    if (it == addrToLine_.end()) {
        return;
    }
    if (it != addrToLine_.begin()) {
        --it;
    }
    // now it either points exactly to the address (if it's found)
    // or to the address just before it (if it isn't found)
    verticalScrollBar()->setValue(it->second.first);
}

QListing::LineInfo QListing::LineInfo::instruction(uint64_t addr, std::string hex, std::string inst, std::string comment) {
    LineInfo info;
    info.type = LineInfo::Type::INSTRUCTION;
    info.d.i.address = addr;
    info.d.i.hex = QString::fromStdString(hex);
    info.d.i.instruction = QString::fromStdString(inst);
    info.d.i.comment = QString::fromStdString(comment);
    return info;
}

QListing::LineInfo QListing::LineInfo::label(std::string label) {
    LineInfo info;
    info.type = LineInfo::Type::LABEL;
    info.d.l.label = QString::fromStdString(label);
    return info;
}

QListing::LineInfo QListing::LineInfo::comment(std::string comment) {
    LineInfo info;
    info.type = LineInfo::Type::COMMENT;
    info.d.c.comment = QString::fromStdString(comment);
    return info;
}
