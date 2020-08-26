// PacketParseDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "PacketParse.h"
#include "PacketParseDlg.h"
#include "PathSelectDlg.h"
#include "..\DiskLib\DiskLib.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CPacketParseDlg 对话框

CPacketParseDlg::CPacketParseDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPacketParseDlg::IDD, pParent)
	, m_radioTypeSel(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPacketParseDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_FILEPATHNAME, m_edtPathFileName);
	DDX_Control(pDX, ID_SOURCE_PATH, m_SourcePath);
	DDX_Control(pDX, ID_DEST_PATH, m_DestPath);
	DDX_Control(pDX, IDC_CREATE_PROGRESS, m_CreateProgress);
	DDX_Control(pDX, IDC_VIEWNAME, m_ViewName);
	DDX_Radio(pDX, IDR_SNAPSHOT_UPDATE, m_radioTypeSel);
}

BEGIN_MESSAGE_MAP(CPacketParseDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDOK, &CPacketParseDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON, &CPacketParseDlg::OnBnClickedButton)
	ON_BN_CLICKED(IDC_SOURCE_BROW, &CPacketParseDlg::OnBnClickedSourceBrow)
	ON_BN_CLICKED(IDC_DEST_BROW, &CPacketParseDlg::OnBnClickedDestBrow)
	ON_BN_CLICKED(IDC_START_UPDATE, &CPacketParseDlg::OnBnClickedStartUpdate)
	ON_BN_CLICKED(IDC_BUTTON1, &CPacketParseDlg::OnBnClickedButton1)
END_MESSAGE_MAP()

#define WM_UPDATE_PROGRESS (WM_USER+0x33)

VOID ProgressReport(PVOID ReportContext, ULONG uFlag, PCHAR FileName, LARGE_INTEGER & UParam)
{
	CPacketParseDlg * Dlg = (CPacketParseDlg *)ReportContext;
	switch(uFlag)
	{
	case PROGRESS_REPORT_START:
		Dlg->m_MaxPieceCount = (LPARAM)(UParam.QuadPart/dwPieceSize) + ((UParam.QuadPart%dwPieceSize) == 0 ? 0 : 1);
		Dlg->m_PieceCount = 0;
		Dlg->m_strViewName.Format("准备创建 [%u\\%u]  名称:%s", Dlg->m_MaxPieceCount, Dlg->m_PieceCount, FileName);
		Dlg->PostMessage(WM_UPDATE_PROGRESS, PROGRESS_REPORT_START, 0);
		break;
	case PROGRESS_REPORT_DISP:
		Dlg->m_PieceCount = (LPARAM)(UParam.QuadPart/dwPieceSize) + ((UParam.QuadPart%dwPieceSize) == 0 ? 0 : 1);
		Dlg->m_strViewName.Format("正在创建 [%u\\%u]  路径:%s", Dlg->m_MaxPieceCount, Dlg->m_PieceCount, FileName);
		Dlg->PostMessage(WM_UPDATE_PROGRESS, PROGRESS_REPORT_DISP, 0);
		break;
	case PROGRESS_REPORT_END:
		break;
	}
}

void CPacketParseDlg::ThreadRouter(PVOID Context)
{
	CPacketParseDlg * Dlg = (CPacketParseDlg *)Context;
	while (TRUE)
	{
		WaitForSingleObject(Dlg->m_WaitEvent, INFINITE);
/*
		PPACKET_CHECK_INFO PacketCheckInfoHead;
		BOOL bResult = DiskLibPacketCheckStart(Dlg->m_strPathFileName.GetBuffer(), &PacketCheckInfoHead, ProgressReport, Dlg);
		if (bResult)
		{
			for (PPACKET_CHECK_INFO Head = PacketCheckInfoHead; Head != NULL; Head = Head->Next)
			{
				::MessageBox(0, Head->FileName, 0, 0);
			}
			DiskLibPacketCheckEnd(PacketCheckInfoHead);
		}
*/

		BOOL bResult = DiskLibCreateIndexFile(Dlg->m_strPathFileName.GetBuffer(), ProgressReport, Dlg);
		if (bResult)
		{
			AfxMessageBox("成功");
		}
		else
		{
			AfxMessageBox("失败");
		}

		ResetEvent(Dlg->m_WaitEvent);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPacketParseDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标显示。
//
HCURSOR CPacketParseDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CPacketParseDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	CPathSelectDlg PathSelectDlg(this, "请选择一个目录");
	if(PathSelectDlg.DoModal())
	{
		m_edtPathFileName.SetWindowText(PathSelectDlg.m_strPath);
	}
}

void CPacketParseDlg::OnBnClickedButton()
{
	// TODO: 在此添加控件通知处理程序代码
	m_edtPathFileName.GetWindowText(m_strPathFileName);
	m_strPathFileName.Trim();
	if (m_strPathFileName == "")
	{
		AfxMessageBox("请输入路径");
		return;
	}
	SetEvent(m_WaitEvent);
}

void CPacketParseDlg::OnBnClickedSourceBrow()
{
	// TODO: 在此添加控件通知处理程序代码
	CPathSelectDlg PathSelectDlg(this, "请选择一个目录");
	if(PathSelectDlg.DoModal())
	{
		m_SourcePath.SetWindowText(PathSelectDlg.m_strPath);
	}
}

void CPacketParseDlg::OnBnClickedDestBrow()
{
	// TODO: 在此添加控件通知处理程序代码
	CPathSelectDlg PathSelectDlg(this, "请选择一个目录");
	if(PathSelectDlg.DoModal())
	{
		m_DestPath.SetWindowText(PathSelectDlg.m_strPath);
	}
}

LRESULT CPacketParseDlg::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	// TODO: 在此添加专用代码和/或调用基类
	if (message == WM_UPDATE_PROGRESS)
	{
		switch(wParam)
		{
		case PROGRESS_REPORT_START:
			m_CreateProgress.SetRange32(0, m_MaxPieceCount);
			m_ViewName.SetWindowText(m_strViewName);
			break;

		case PROGRESS_REPORT_DISP:
			m_CreateProgress.SetPos(m_PieceCount);
			m_ViewName.SetWindowText(m_strViewName);
		    break;
		}
	}
	return CDialog::WindowProc(message, wParam, lParam);
}

void CPacketParseDlg::OnBnClickedStartUpdate()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	m_SourcePath.GetWindowText(m_strSourcePath);
	m_DestPath.GetWindowText(m_strDestPath);
	SetEvent(m_UpdateWaitEvent);
}



VOID CopyProgressReport(PVOID ReportContext, ULONG uFlag, PCHAR FileName, LARGE_INTEGER & UParam)
{
	CPacketParseDlg * Dlg = (CPacketParseDlg *)ReportContext;
	switch(uFlag)
	{
	case PROGRESS_REPORT_START:
		Dlg->m_MaxPieceCount = (LPARAM)UParam.QuadPart;
		Dlg->m_PieceCount = 0;
		Dlg->m_strViewName.Format("开始复制 [%u\\%u] 名称:%s", Dlg->m_MaxPieceCount, Dlg->m_PieceCount, FileName);
		Dlg->PostMessage(WM_UPDATE_PROGRESS, PROGRESS_REPORT_START, 0);
		break;
	case PROGRESS_REPORT_DISP:
		Dlg->m_PieceCount = (LPARAM)UParam.QuadPart;
		Dlg->m_strViewName.Format("正在复制 [%u\\%u] 路径:%s", Dlg->m_MaxPieceCount, Dlg->m_PieceCount, FileName);
		Dlg->PostMessage(WM_UPDATE_PROGRESS, PROGRESS_REPORT_DISP, 0);
		break;
	case PROGRESS_REPORT_END:
		break;

	case CHECKPROGRESS_REPORT_START:
		Dlg->m_MaxPieceCount = (LPARAM)UParam.QuadPart;
		Dlg->m_PieceCount = 0;
		Dlg->m_strViewName.Format("开始检查文件 [%u\\%u] 名称:%s", Dlg->m_MaxPieceCount, Dlg->m_PieceCount, FileName);
		Dlg->PostMessage(WM_UPDATE_PROGRESS, PROGRESS_REPORT_START, 0);
		break;
	case CHECKPROGRESS_REPORT_DISP:
		Dlg->m_PieceCount = (LPARAM)UParam.QuadPart;
		Dlg->m_strViewName.Format("正在检查文件 [%u\\%u] 路径:%s", Dlg->m_MaxPieceCount, Dlg->m_PieceCount, FileName);
		Dlg->PostMessage(WM_UPDATE_PROGRESS, PROGRESS_REPORT_DISP, 0);
		break;
	}
}

void CPacketParseDlg::UpdateThreadRouter(PVOID Context)
{
	BOOL bResult = FALSE;;
	CPacketParseDlg * Dlg = (CPacketParseDlg *)Context;
	while (TRUE)
	{
		WaitForSingleObject(Dlg->m_UpdateWaitEvent, INFINITE);
		DiskLibEnableThroughWrite();
		switch(Dlg->m_radioTypeSel)
		{
		case 0:
			bResult = DiskLibSnapshotUpdate(Dlg->m_strSourcePath.GetBuffer(), Dlg->m_strDestPath.GetBuffer(), CopyProgressReport, Dlg);
			break;
		case 1:
			bResult = DiskLibRepairUpdate(Dlg->m_strSourcePath.GetBuffer(), Dlg->m_strDestPath.GetBuffer(), CopyProgressReport, Dlg);
			break;
		case 2:
			bResult = DiskLibCompleteUpdate(Dlg->m_strSourcePath.GetBuffer(), Dlg->m_strDestPath.GetBuffer(), CopyProgressReport, Dlg);
		    break;
		}
		DiskLibDisableThroughWrite();
		if (bResult)
		{
			AfxMessageBox("成功");
		}
		else
		{
			AfxMessageBox("失败");	
		}
		ResetEvent(Dlg->m_UpdateWaitEvent);
	}
}

// CPacketParseDlg 消息处理程序
BOOL CPacketParseDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_WaitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	_beginthread(ThreadRouter, 0, this);

	m_UpdateWaitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	_beginthread(UpdateThreadRouter, 0, this);

	DiskLibInitialize();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CPacketParseDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	//设置保护状态
	DiskLibSetProtectState(FALSE, FALSE);
	MessageBox("OK");
}
