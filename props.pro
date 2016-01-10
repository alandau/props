#-------------------------------------------------
#
# Project created by QtCreator 2015-11-13T12:07:58
#
#-------------------------------------------------

QT       += core gui
CONFIG += c++11

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = props
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    fileformat_elf.cpp \
    listing.cpp \
    qlisting.cpp

HEADERS  += mainwindow.h \
    elf.h \
    fileformat.h \
    fileformat_elf.h \
    listingiface.h \
    listing.h \
    qlisting.h \
    optional.h

FORMS    += mainwindow.ui

INCLUDEPATH += distorm/include

LIBS += ../distorm/distorm3.a
