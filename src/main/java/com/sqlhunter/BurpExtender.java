package com.sqlhunter;

import burp.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel mainPanel;
    private JCheckBox liveCheckBox;
    private JTable logTable;
    private DefaultTableModel tableModel;

    private final List<IHttpRequestResponse> queue = new CopyOnWriteArrayList<IHttpRequestResponse>();
    private final Set<String> processedKeys = new HashSet<String>();

    private static final String[] COLUMNS = new String[]{"时间", "主机", "路径", "参数", "类型", "证据", "状态"};

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("SQL Hunter (Java8)");
        buildUi();

        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.addSuiteTab(this);
        callbacks.printOutput("[SQL Hunter] Java extension loaded.");
    }

    private void buildUi() {
        mainPanel = new JPanel(new BorderLayout());

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.X_AXIS));

        liveCheckBox = new JCheckBox("被动监听实时流量", false);
        JButton scanHistoryButton = new JButton("扫描 Proxy History");
        scanHistoryButton.addActionListener(this::onScanHistory);

        JButton activeButton = new JButton("主动检测选中请求");
        activeButton.addActionListener(this::onActiveSelected);

        top.add(liveCheckBox);
        top.add(Box.createHorizontalStrut(8));
        top.add(scanHistoryButton);
        top.add(Box.createHorizontalStrut(8));
        top.add(activeButton);

        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        logTable = new JTable(tableModel);
        JScrollPane scrollPane = new JScrollPane(logTable);

        mainPanel.add(top, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
    }

    @Override
    public String getTabCaption() {
        return "SQL Hunter";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || !liveCheckBox.isSelected()) {
            return;
        }

        String key = requestKey(messageInfo);
        synchronized (processedKeys) {
            if (processedKeys.contains(key)) {
                return;
            }
            processedKeys.add(key);
        }

        enqueue(messageInfo);
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        JMenuItem sendItem = new JMenuItem("Send to SQL Hunter (Active SQLi Check)");
        sendItem.addActionListener(e -> {
            IHttpRequestResponse[] selected = invocation.getSelectedMessages();
            if (selected == null || selected.length == 0) {
                return;
            }
            for (IHttpRequestResponse item : selected) {
                enqueue(item);
            }
            appendLog("-", "-", "-", "-", "-", "已加入主动检测队列", "INFO");
        });

        List<JMenuItem> items = new ArrayList<JMenuItem>();
        items.add(sendItem);
        return items;
    }

    private void onScanHistory(ActionEvent event) {
        IHttpRequestResponse[] history = callbacks.getProxyHistory();
        if (history == null || history.length == 0) {
            JOptionPane.showMessageDialog(mainPanel, "Proxy History 为空");
            return;
        }

        int count = 0;
        for (IHttpRequestResponse item : history) {
            String key = requestKey(item);
            boolean isNew;
            synchronized (processedKeys) {
                isNew = !processedKeys.contains(key);
                if (isNew) {
                    processedKeys.add(key);
                }
            }
            if (isNew) {
                enqueue(item);
                count++;
            }
        }

        JOptionPane.showMessageDialog(mainPanel, "已加入检测队列: " + count);
    }

    private void onActiveSelected(ActionEvent event) {
        int row = logTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请先在结果表中选中一条记录（来自实时流量/History/右键发送）");
            return;
        }

        final String host = String.valueOf(tableModel.getValueAt(row, 1));
        final String path = String.valueOf(tableModel.getValueAt(row, 2));

        for (IHttpRequestResponse item : queue) {
            IRequestInfo info = helpers.analyzeRequest(item);
            URL url = info.getUrl();
            if (url != null && host.equals(url.getHost()) && path.equals(url.getPath())) {
                new Thread(() -> runActiveChecks(item)).start();
                JOptionPane.showMessageDialog(mainPanel, "已开始主动检测");
                return;
            }
        }

        JOptionPane.showMessageDialog(mainPanel, "未找到对应请求，请使用右键 Send to SQL Hunter");
    }

    private void enqueue(IHttpRequestResponse messageInfo) {
        queue.add(messageInfo);
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        URL url = requestInfo.getUrl();

        List<IParameter> parameters = requestInfo.getParameters();
        String firstParam = parameters.isEmpty() ? "-" : parameters.get(0).getName();

        appendLog(now(), safe(url == null ? null : url.getHost()), safe(url == null ? null : url.getPath()),
                firstParam, "待检测", "请求已收集", "PENDING");
    }

    private void runActiveChecks(IHttpRequestResponse baseMessage) {
        IRequestInfo requestInfo = helpers.analyzeRequest(baseMessage);
        URL url = requestInfo.getUrl();
        String host = safe(url == null ? null : url.getHost());
        String path = safe(url == null ? null : url.getPath());

        List<IParameter> params = requestInfo.getParameters();
        if (params == null || params.isEmpty()) {
            appendLog(now(), host, path, "-", "-", "无可注入参数", "SKIP");
            return;
        }

        byte[] baseResp = baseMessage.getResponse();
        if (baseResp == null) {
            appendLog(now(), host, path, "-", "-", "基线响应为空", "SKIP");
            return;
        }

        IResponseInfo baseInfo = helpers.analyzeResponse(baseResp);
        short baseStatus = baseInfo.getStatusCode();
        String baseBody = helpers.bytesToString(slice(baseResp, baseInfo.getBodyOffset()));

        boolean found = false;

        for (IParameter parameter : params) {
            String name = parameter.getName();
            String value = parameter.getValue();

            IHttpRequestResponse errorResp = sendPayload(baseMessage, parameter, value + "'");
            if (errorResp != null && isErrorBased(baseStatus, baseBody, errorResp.getResponse())) {
                found = true;
                markVuln(errorResp, "red", "Error-based SQLi confirmed");
                appendLog(now(), host, path, name, "报错注入", "发现数据库报错特征", "VULN");
                reportIssue(errorResp, "Error-based SQL Injection", name, "High");
            }

            IHttpRequestResponse trueResp = sendPayload(baseMessage, parameter, value + "' AND '1'='1");
            IHttpRequestResponse falseResp = sendPayload(baseMessage, parameter, value + "' AND '1'='2");
            if (trueResp != null && falseResp != null && isBooleanBlind(baseResp, trueResp.getResponse(), falseResp.getResponse())) {
                found = true;
                markVuln(falseResp, "yellow", "Boolean blind SQLi confirmed");
                appendLog(now(), host, path, name, "盲注", "真/假条件响应差异显著", "VULN");
                reportIssue(falseResp, "Boolean-based Blind SQL Injection", name, "High");
            }

            long start = System.currentTimeMillis();
            IHttpRequestResponse slowResp = sendPayload(baseMessage, parameter, value + "'; WAITFOR DELAY '0:0:5'--");
            long elapsed = System.currentTimeMillis() - start;
            if (slowResp != null && elapsed >= 4500L) {
                found = true;
                markVuln(slowResp, "orange", "Time blind SQLi confirmed");
                appendLog(now(), host, path, name, "时间盲注", "响应延时 " + (elapsed / 1000.0) + "s", "VULN");
                reportIssue(slowResp, "Time-based Blind SQL Injection", name, "High");
            }
        }

        if (!found) {
            appendLog(now(), host, path, "-", "-", "未确认 SQL 注入", "CLEAN");
        }
    }

    private IHttpRequestResponse sendPayload(IHttpRequestResponse base, IParameter parameter, String payloadValue) {
        IParameter newParameter = helpers.buildParameter(parameter.getName(), payloadValue, parameter.getType());
        byte[] request = helpers.updateParameter(base.getRequest(), newParameter);
        return callbacks.makeHttpRequest(base.getHttpService(), request);
    }

    private boolean isErrorBased(short baseStatus, String baseBody, byte[] response) {
        if (response == null) {
            return false;
        }
        IResponseInfo respInfo = helpers.analyzeResponse(response);
        short status = respInfo.getStatusCode();
        String body = helpers.bytesToString(slice(response, respInfo.getBodyOffset()));

        String[] patterns = new String[]{
                "SQL syntax",
                "warning.*mysql",
                "unclosed quotation",
                "quoted string not properly terminated",
                "PG::SyntaxError",
                "ODBC SQL Server Driver",
                "SQLite/JDBCDriver",
                "You have an error in your SQL syntax"
        };

        for (String p : patterns) {
            if (Pattern.compile(p, Pattern.CASE_INSENSITIVE).matcher(body).find()) {
                return true;
            }
        }

        return status >= 500 && baseStatus < 500 && Math.abs(body.length() - baseBody.length()) > 50;
    }

    private boolean isBooleanBlind(byte[] baseResp, byte[] trueResp, byte[] falseResp) {
        if (baseResp == null || trueResp == null || falseResp == null) {
            return false;
        }

        IResponseInfo b = helpers.analyzeResponse(baseResp);
        IResponseInfo t = helpers.analyzeResponse(trueResp);
        IResponseInfo f = helpers.analyzeResponse(falseResp);

        short bStatus = b.getStatusCode();
        short tStatus = t.getStatusCode();
        short fStatus = f.getStatusCode();

        String bBody = helpers.bytesToString(slice(baseResp, b.getBodyOffset()));
        String tBody = helpers.bytesToString(slice(trueResp, t.getBodyOffset()));
        String fBody = helpers.bytesToString(slice(falseResp, f.getBodyOffset()));

        boolean statusDiff = (tStatus == bStatus && fStatus != bStatus) || (tStatus != fStatus);
        boolean lenDiff = Math.abs(tBody.length() - fBody.length()) > Math.max(30, (int) (bBody.length() * 0.05));
        return statusDiff || lenDiff;
    }

    private void markVuln(IHttpRequestResponse item, String color, String comment) {
        item.setHighlight(color);
        item.setComment(comment);
    }

    private void reportIssue(IHttpRequestResponse item, String issueName, String paramName, String severity) {
        URL url = helpers.analyzeRequest(item).getUrl();
        callbacks.addScanIssue(new CustomScanIssue(
                item.getHttpService(),
                url,
                new IHttpRequestResponse[]{item},
                issueName,
                "Parameter <b>" + paramName + "</b> appears injectable.",
                severity
        ));
    }

    private void appendLog(String time, String host, String path, String param, String type, String evidence, String status) {
        SwingUtilities.invokeLater(() -> tableModel.addRow(new Object[]{time, host, path, param, type, evidence, status}));
    }

    private String requestKey(IHttpRequestResponse item) {
        IRequestInfo info = helpers.analyzeRequest(item);
        URL url = info.getUrl();
        return info.getMethod() + " " + String.valueOf(url);
    }

    private String now() {
        return String.valueOf(System.currentTimeMillis() / 1000L);
    }

    private String safe(String value) {
        return value == null ? "-" : value;
    }

    private byte[] slice(byte[] raw, int offset) {
        if (raw == null || offset < 0 || offset >= raw.length) {
            return new byte[0];
        }
        int len = raw.length - offset;
        byte[] result = new byte[len];
        System.arraycopy(raw, offset, result, 0, len);
        return result;
    }

    private static class CustomScanIssue implements IScanIssue {
        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse[] httpMessages;
        private final String issueName;
        private final String issueDetail;
        private final String severity;

        public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages,
                               String issueName, String issueDetail, String severity) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.issueName = issueName;
            this.issueDetail = issueDetail;
            this.severity = severity;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return issueName;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return "Firm";
        }

        @Override
        public String getIssueBackground() {
            return "SQL injection allows attackers to interfere with backend queries.";
        }

        @Override
        public String getRemediationBackground() {
            return "Use parameterized queries and strict input validation.";
        }

        @Override
        public String getIssueDetail() {
            return issueDetail;
        }

        @Override
        public String getRemediationDetail() {
            return "Refactor dynamic SQL and centralize safe data-access wrappers.";
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }
    }
}
