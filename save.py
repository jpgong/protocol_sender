#!/usr/bin/env python
# coding:utf-8
"""
  Author:  u"王浩" --<823921498@qq.com>
  Purpose: u"文件选择，保存"
  Created: 2014/8/26
"""

import os
import wx

wildcard = u"Python 文件 (*.py)|*.py|" \
           u"编译的 Python 文件 (*.pyc)|*.pyc|" \
           u" 垃圾邮件文件 (*.spam)|*.spam|" \
           "Egg file (*.egg)|*.egg|" \
           "All files (*.*)|*.*"


###############################################################################
class FileDialog(wx.Frame):
    """文件选择，保存"""

    # ----------------------------------------------------------------------
    def __init__(self):
        """Constructor"""
        wx.Frame.__init__(self, None, -1)
        b1 = wx.Button(self, -1, u"选择文件", (50, 50))
        self.Bind(wx.EVT_BUTTON, self.OnButton1, b1)

        b2 = wx.Button(self, -1, u"保存文件", (50, 90))
        self.Bind(wx.EVT_BUTTON, self.OnButton2, b2)

    # ----------------------------------------------------------------------
    def OnButton1(self, event):
        """"""
        dlg = wx.FileDialog(self, message=u"选择文件",
                            defaultDir=os.getcwd(),
                            defaultFile="",
                            wildcard=wildcard,
                            )

        if dlg.ShowModal() == wx.ID_OK:
            paths = dlg.GetPaths()  # 返回一个list，如[u'E:\\test_python\\Demo\\ColourDialog.py', u'E:\\test_python\\Demo\\DirDialog.py']
            print
            paths
            for path in paths:
                print
                path  # E:\test_python\Demo\ColourDialog.py E:\test_python\Demo\DirDialog.py

        dlg.Destroy()

    # ----------------------------------------------------------------------
    def OnButton2(self, event):
        """"""
        dlg = wx.FileDialog(self, message=u"保存文件",
                            defaultDir=os.getcwd(),
                            defaultFile="",
                            wildcard=wildcard,
                            style=wx.ART_FILE_SAVE)
        dlg.SetFilterIndex(0)  # 设置默认保存文件格式，这里的0是py，1是pyc
        dlg.ShowModal()
        dlg.Destroy()


###############################################################################
if __name__ == '__main__':
    frame = wx.PySimpleApp()
    app = FileDialog()
    app.Show()
    frame.MainLoop()
