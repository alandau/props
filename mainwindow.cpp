#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "fileformat_elf.h"
#include <QStandardItemModel>
#include <QAbstractTableModel>
#include <QMessageBox>
#include <QDockWidget>
#include <QTableView>
#include <QFontDatabase>
#include <QStyledItemDelegate>
#include <QTextDocument>
#include <QAbstractTextDocumentLayout>
#include <QPainter>

class HtmlDelegate : public QStyledItemDelegate
{
protected:
    void paint ( QPainter * painter, const QStyleOptionViewItem & option, const QModelIndex & index ) const;
    QSize sizeHint ( const QStyleOptionViewItem & option, const QModelIndex & index ) const;
};

void HtmlDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItemV4 optionV4 = option;
    initStyleOption(&optionV4, index);

    QStyle *style = optionV4.widget? optionV4.widget->style() : QApplication::style();

    QTextDocument doc;
    doc.setHtml("<tt>" + optionV4.text + "</tt>");

    /// Painting item without text
    optionV4.text = QString();
    style->drawControl(QStyle::CE_ItemViewItem, &optionV4, painter);

    QAbstractTextDocumentLayout::PaintContext ctx;

    // Highlighting text if item is selected
    if (optionV4.state & QStyle::State_Selected)
        ctx.palette.setColor(QPalette::Text, optionV4.palette.color(QPalette::Active, QPalette::HighlightedText));

    QRect textRect = style->subElementRect(QStyle::SE_ItemViewItemText, &optionV4);
    painter->save();
    painter->translate(textRect.topLeft());
    painter->setClipRect(textRect.translated(-textRect.topLeft()));
    doc.documentLayout()->draw(painter, ctx);
    painter->restore();
}

QSize HtmlDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyleOptionViewItemV4 optionV4 = option;
    initStyleOption(&optionV4, index);

    QTextDocument doc;
    doc.setHtml("<tt>" + optionV4.text + "</tt>");
    doc.setTextWidth(optionV4.rect.width());
    return QSize(doc.idealWidth(), doc.size().height());
}

class MyModel : public QAbstractTableModel {
public:

    explicit MyModel(Listing& listing, Symtab& symtab, QObject* parent = 0)
        : QAbstractTableModel(parent)
        , listing_(listing)
        , symtab_(symtab)
    {}

#if 0
    QModelIndex index(int row, int column, const QModelIndex& /*parent*/ = QModelIndex()) const override {
        return createIndex(row, column);
    }
#endif

    int rowCount(const QModelIndex& /*parent*/ = QModelIndex()) const override {
        return listing_.size();
    }

    int columnCount(const QModelIndex& /*parent*/ = QModelIndex()) const override {
        return 2;
    }

    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override {
        if (role == Qt::DisplayRole) {
            auto p = rowToAddress(index.row());
            Listing::Data data = listing_.getData(p.first);
            switch (index.column()) {
            case 0: return p.second == 0 ? QString::fromStdString(data.hex) : p.second < data.comments.size() + 1 ? QString() : QString("<font color=purple>%1:</font>").arg(QString::fromStdString(symtab_.get(p.first)[p.second - 1 - data.comments.size()]));
            case 1: return p.second == 0
                        ? QString::fromStdString(data.instruction) +
                          (data.instructionComment.empty() ? QString() : " <font color=green>; " + QString::fromStdString(data.instructionComment) + "</font>")
                        : p.second < data.comments.size() + 1 ? "<font color=green>; " + QString::fromStdString(data.comments[p.second - 1]) + "</font>" : "";
            }
        } else if (role == Qt::FontRole) {
            return QFontDatabase::systemFont(QFontDatabase::FixedFont);
        }
        return QVariant();
    }

    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override {
        if (orientation == Qt::Horizontal) {
            if (role == Qt::DisplayRole) {
                switch (section) {
                case 0: return "Bytes";
                case 1: return "Instruction";
                }
            }
        } else if (orientation == Qt::Vertical) {
            if (role == Qt::DisplayRole) {
                auto p = rowToAddress(section);
                if (p.second == 0) {
                    // actual instruction
                    return QString("%1").arg(p.first, 0, 16);
                } else {
                    // comment or label
                    return QString();
                }
            } else if (role == Qt::FontRole) {
                return QFontDatabase::systemFont(QFontDatabase::FixedFont);
            } else if (role == Qt::TextAlignmentRole) {
                return Qt::AlignRight;
            }
        }
        return QVariant();
    }

    std::pair<uint64_t,uint32_t> rowToAddress(int row) const {
        return listing_.rowToAddress(static_cast<size_t>(row));
    }

private:
    Listing& listing_;
    Symtab& symtab_;
};

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui_(new Ui::MainWindow)
    , filename_("/bin/true")
    , file_(filename_)
    , listing_(symtab_)
{
    ui_->setupUi(this);
    setCentralWidget(ui_->listingView);

    parseElfHeader();

    fileFormat_->disassemble(listing_, symtab_);
    ui_->listingView->setData(&listing_, &symtab_);
    ui_->listingView->scrollToAddress(fileFormat_->getMetadata().entryPoint);

    ui_->listingTable->setModel(new MyModel(listing_, symtab_, ui_->listingTable));
    ui_->listingTable->resizeColumnsToContents();
    ui_->listingTable->resizeRowsToContents();
    ui_->listingTable->setItemDelegate(new HtmlDelegate());
}

void MainWindow::parseElfHeader() {
    if (!file_.open(QFile::ReadOnly)) {
        QMessageBox::critical(this, "Error", "Can't open file: " + filename_);
        return;
    }
    size_t size = file_.size();
    const void* data = file_.map(0, size);
    file_.close();
    fileFormat_.reset(new ELFFileFormat(data, size));

    FileFormat::Metadata metadata = fileFormat_->getMetadata();
    for (const FileFormat::Table& table : metadata.tables) {
        QStandardItemModel* model = new QStandardItemModel(this);
        model->setColumnCount(table.headers.size());
        for (size_t i = 0; i < table.headers.size(); i++) {
            model->setHeaderData(i, Qt::Horizontal, QString::fromStdString(table.headers[i]), Qt::DisplayRole);
        }
        for (const auto& row : table.items) {
            QList<QStandardItem*> rowItems;
            for (size_t i = 0; i < row.size(); i++) {
                QStandardItem* cell = new QStandardItem(QString::fromStdString(row[i]));
                rowItems.append(cell);
            }
            model->appendRow(rowItems);
        }

        QDockWidget* dock = new QDockWidget(this);
        QTableView* tv = new QTableView(dock);
        tv->setShowGrid(true);
        tv->setGridStyle(Qt::SolidLine);
        tv->setAlternatingRowColors(true);
        tv->setModel(model);
        tv->resizeColumnsToContents();
        tv->resizeRowsToContents();
        tv->setEditTriggers(QAbstractItemView::NoEditTriggers);
        dock->setWindowTitle(QString::fromStdString(table.name));
        dock->setWidget(tv);
        addDockWidget(Qt::RightDockWidgetArea, dock);
    }
}

MainWindow::~MainWindow() {
}
