#ifndef QLISTING_H
#define QLISTING_H

#include <QAbstractScrollArea>
#include "listing.h"

class QListing : public QAbstractScrollArea
{
    Q_OBJECT
    // Q_PROPERTY(bool addressArea READ addressArea WRITE setAddressArea)

public:
    QListing(QWidget* parent = nullptr);
    void setData(const Listing* listing, const Symtab* symtab);
    ~QListing();

    void setFont(const QFont& font);
    void scrollToAddress(uint64_t address);
protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;

private:
    struct LineInfo {
        enum class Type {INSTRUCTION, COMMENT, LABEL};
        static LineInfo instruction(uint64_t addr, std::string hex, std::string inst, std::string comment);
        static LineInfo comment(std::string comment);
        static LineInfo label(std::string label);

        LineInfo();
        ~LineInfo();
        Type type;
        struct {
            struct {
                uint64_t address;
                QString hex;
                QString instruction;
                QString comment;
            } i;
            struct {
                QString comment;
            } c;
            struct {
               QString label;
            } l;
        } d;
    };

    const Listing* listing_ = nullptr;
    const Symtab* symtab_ = nullptr;
    const Listing::Segment* segment_;
    std::vector<LineInfo> lines_;
    std::map<uint64_t, std::pair<int,int>> addrToLine_;

    int pxCharWidth_, pxCharHeight_;
    int pxAddrWidth_;
    int numRows_;

    QColor regularColor_ = Qt::black;
    QColor labelColor_ = Qt::darkMagenta;
    QColor commentColor_ = Qt::darkGreen;
    std::vector<QColor> arrowColors_ = {Qt::blue, Qt::green, Qt::red, Qt::magenta, Qt::cyan, Qt::gray, Qt::black, Qt::darkYellow};

    void calculate();
    void drawRefline(QPainter& painter, int row1, int row2, int indent, int x, QColor color, bool conditional);
    void drawArrow(QPainter& painter, int line, int x, Qt::ArrowType arrowType);

private slots:
    void adjust();
};

#endif // QLISTING_H

