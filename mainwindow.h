#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFile>
#include <memory>
#include "fileformat.h"
#include "listing.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    std::unique_ptr<Ui::MainWindow> ui_;
    QString filename_;
    QFile file_;
    std::unique_ptr<FileFormat> fileFormat_;
    Symtab symtab_;
    Listing listing_;

    void parseElfHeader();
};

#endif // MAINWINDOW_H
