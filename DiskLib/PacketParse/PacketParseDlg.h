// PacketParseDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"


// CPacketParseDlg 对话框
class CPacketParseDlg : public CDialog
{
// 构造
public:
	CPacketParseDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_PACKETPARSE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	CEdit m_edtPathFileName;
	afx_msg void OnBnClickedButton();
	CEdit m_SourcePath;
	CEdit m_DestPath;
	afx_msg void OnBnClickedSourceBrow();
	afx_msg void OnBnClickedDestBrow();
	static void ThreadRouter(PVOID Context);
	static void UpdateThreadRouter(PVOID Context);
	CString m_strPathFileName;
	CString m_strIndexFileName;

	CString m_strSourcePath;
	CString m_strDestPath;

	CString m_strViewName;
	ULONG m_PieceCount;
	ULONG m_MaxPieceCount;
private:
	HANDLE m_WaitEvent;
	HANDLE m_UpdateWaitEvent;
public:
	CProgressCtrl m_CreateProgress;
protected:
	virtual LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam);
public:
	CStatic m_ViewName;
	afx_msg void OnBnClickedRadio3();
	afx_msg void OnBnClickedStartUpdate();
	int m_radioTypeSel;
	afx_msg void OnBnClickedButton1();
};
