#include "qlisting.h"
#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QMessageBox>

QListing::QListing(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    setFont(QFont("Monospace"));
    connect(verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(adjust()));
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

void QListing::paintEvent(QPaintEvent* /*event*/) {
    if (listing_ == nullptr) {
        return;
    }
    QPainter painter(viewport());
    painter.fillRect(0, 0, pxAddrWidth_ + pxCharWidth_ / 2, viewport()->height(), palette().window().color());

    int hexWidthInChars = 20;

    int hexLeft = pxAddrWidth_ + pxCharWidth_;
    int hexWidth = hexWidthInChars * pxCharWidth_;
    int instLeft = hexLeft + hexWidth + 2 * pxCharWidth_;
    int labelLeft = instLeft - 3 * pxCharWidth_;

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
        case LineInfo::Type::LABEL: {
            painter.setPen(labelColor_);
            painter.drawText(labelLeft, y, info.d.l.label + ":");
            break;
        }
        case LineInfo::Type::COMMENT: {
            painter.setPen(commentColor_);
            painter.drawText(instLeft, y, "; " + info.d.c.comment);
            break;
        }
        }
        y += pxCharHeight_;
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
    if (Optional<uint64_t> to = listing_->getBranch(info.d.i.address)) {
        scrollToAddress(to.get());
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
        addrToLine_[addr] = lines_.size();
        ListingIface::Data data = listing_->getData(addr);
        if (data.length == 0) {
            // no instruction at this address, treat as data
            size_t offset = segment_->addrToOffset(addr);
            uint8_t byte = offset < segment_->data.size() ? segment_->data[offset] : 0;
            std::string hex = QString("%1").arg(byte, 2, 16, QLatin1Char('0')).toStdString();
            lines_.push_back(LineInfo::instruction(addr, hex, "db 0x" + hex, ""));
            addr++;
            continue;
        }

        for (const std::string& comment : data.comments) {
            lines_.push_back(LineInfo::comment(comment));
        }

        for (const std::string& label : symtab_->get(addr)) {
            lines_.push_back(LineInfo::label(label));
        }

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
    verticalScrollBar()->setValue(it->second);
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
