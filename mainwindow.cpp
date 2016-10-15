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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui_(new Ui::MainWindow)
    , filename_(qApp->arguments().size() == 2 ? qApp->arguments().at(1) : "/bin/true")
    , file_(filename_)
    , listing_(symtab_)
{
    ui_->setupUi(this);
    setWindowTitle(windowTitle() + " - " + filename_);
    setCentralWidget(ui_->listingView);

    parseElfHeader();

    fileFormat_->loadSymbols(symtab_);
    uint64_t entryPoint = fileFormat_->getMetadata().entryPoint;
    symtab_.insert(entryPoint, "entry");
    fileFormat_->disassemble(listing_, symtab_);
    fileFormat_->findFeatures(listing_, symtab_);
    fileFormat_->recalcCommentsAfterSymtabChange(listing_, symtab_);
    ui_->listingView->setData(&listing_, &symtab_);
    ui_->listingView->scrollToAddress(entryPoint);
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
