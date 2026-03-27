package com.sqlhunter;

import burp.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

    private static final String EXT_NAME = "SQL Hunter (Java8)";
    private static final String TAB_NAME = "SQL Hunter";

    private static final String[] COLUMNS =
            new String[]{"时间", "主机", "路径", "参数", "类型", "证据", "状态"};

    private static final String[] ERROR_SUFFIXES = new String[]{
            "'", "\"", "'/**/", "'))"
    };

    private static final PayloadPair[] BOOLEAN_PAIRS = new PayloadPair[]{
            new PayloadPair("basic-and", "' AND '1'='1", "' AND '1'='2"),
            new PayloadPair("inline-comment", "'/**/AND/**/'1'='1", "'/**/AND/**/'1'='2"),
            new PayloadPair("or-comment", "' OR 1=1-- ", "' OR 1=2-- "),
            new PayloadPair("close-paren", "') OR ('1'='1", "') OR ('1'='2")
    };

    private static final String[] TIME_SUFFIXES = new String[]{
            "'; WAITFOR DELAY '0:0:5'--",
            "';WAITFOR/**/DELAY/**/'0:0:5'--",
            "' AND SLEEP(5)-- ",
            "'||pg_sleep(5)--"
    };

    private static final Pattern[] ERROR_PATTERNS = new Pattern[]{
            Pattern.compile("SQL syntax", Pattern.CASE_INSENSITIVE),
            Pattern.compile("warning.*mysql", Pattern.CASE_INSENSITIVE),
            Pattern.compile("unclosed quotation", Pattern.CASE_INSENSITIVE),
            Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE),
            Pattern.compile("PG::SyntaxError", Pattern.CASE_INSENSITIVE),
            Pattern.compile("ODBC SQL Server Driver", Pattern.CASE_INSENSITIVE),
            Pattern.compile("SQLite/JDBCDriver", Pattern.CASE_INSENSITIVE),
            Pattern.compile("You have an error in your SQL syntax", Pattern.CASE_INSENSITIVE)
    };

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel mainPanel;
    private JCheckBox liveCheckBox;
    private JTable logTable;
    private DefaultTableModel tableModel;
    private JButton pauseResumeButton;

    private final List<IHttpRequestResponse> capturedQueue = new CopyOnWriteArrayList<IHttpRequestResponse>();
    private final Set<String> processedKeys = new HashSet<String>();
    private final List<Future<?>> runningTasks = new CopyOnWriteArrayList<Future<?>>();

    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private final Object pauseLock = new Object();

    private ExecutorService activeExecutor;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.activeExecutor = Executors.newFixedThreadPool(2);

        callbacks.setExtensionName(EXT_NAME);
        buildUi();

        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.addSuiteTab(this);
        callbacks.registerExtensionStateListener(this::shutdownExtension);
        callbacks.printOutput("[SQL Hunter] loaded.");
    }

    @Override
    public String getTabCaption() {
        return TAB_NAME;
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
            if (!processedKeys.add(key)) {
                return;
            }
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
            appendLog("-", "-", "-", "-", "控制", "已加入主动检测队列", "INFO");
        });

        List<JMenuItem> items = new ArrayList<JMenuItem>();
        items.add(sendItem);
        return items;
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

        pauseResumeButton = new JButton("暂停检测");
        pauseResumeButton.addActionListener(this::onPauseResume);

        JButton stopButton = new JButton("停止检测");
        stopButton.addActionListener(this::onStopAll);

        top.add(liveCheckBox);
        top.add(Box.createHorizontalStrut(8));
        top.add(scanHistoryButton);
        top.add(Box.createHorizontalStrut(8));
        top.add(activeButton);
        top.add(Box.createHorizontalStrut(8));
        top.add(pauseResumeButton);
        top.add(Box.createHorizontalStrut(8));
        top.add(stopButton);

        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        logTable = new JTable(tableModel);
        mainPanel.add(top, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(logTable), BorderLayout.CENTER);
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
            synchronized (processedKeys) {
                if (!processedKeys.add(key)) {
                    continue;
                }
            }
            enqueue(item);
            count++;
        }

        JOptionPane.showMessageDialog(mainPanel, "已加入检测队列: " + count);
    }

    private void onActiveSelected(ActionEvent event) {
        int row = logTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请先选中一条记录");
            return;
        }

        String host = String.valueOf(tableModel.getValueAt(row, 1));
        String path = String.valueOf(tableModel.getValueAt(row, 2));

        IHttpRequestResponse selected = findCapturedMessage(host, path);
        if (selected == null) {
            JOptionPane.showMessageDialog(mainPanel, "未找到对应请求，请使用右键 Send to SQL Hunter");
            return;
        }

        submitActiveCheck(selected);
        JOptionPane.showMessageDialog(mainPanel, "已提交主动检测任务");
    }

    private IHttpRequestResponse findCapturedMessage(String host, String path) {
        for (IHttpRequestResponse item : capturedQueue) {
            IRequestInfo info = helpers.analyzeRequest(item);
            URL url = info.getUrl();
            if (url != null && host.equals(url.getHost()) && path.equals(url.getPath())) {
                return item;
            }
        }
        return null;
    }

    private void onPauseResume(ActionEvent event) {
        if (paused.compareAndSet(false, true)) {
            pauseResumeButton.setText("恢复检测");
            appendLog(now(), "-", "-", "-", "控制", "主动检测已暂停", "PAUSE");
            return;
        }

        paused.set(false);
        synchronized (pauseLock) {
            pauseLock.notifyAll();
        }
        pauseResumeButton.setText("暂停检测");
        appendLog(now(), "-", "-", "-", "控制", "主动检测已恢复", "RESUME");
    }

    private void onStopAll(ActionEvent event) {
        stopAllTasks();
        JOptionPane.showMessageDialog(mainPanel, "已停止当前主动检测任务");
    }

    private void submitActiveCheck(final IHttpRequestResponse item) {
        stopRequested.set(false);
        Future<?> task = activeExecutor.submit(() -> {
            try {
                runActiveChecks(item);
            } finally {
                runningTasks.removeIf(f -> f.isDone() || f.isCancelled());
            }
        });
        runningTasks.add(task);
    }

    private void stopAllTasks() {
        stopRequested.set(true);
        paused.set(false);
        synchronized (pauseLock) {
            pauseLock.notifyAll();
        }

        for (Future<?> task : runningTasks) {
            task.cancel(true);
        }
        runningTasks.clear();
        appendLog(now(), "-", "-", "-", "控制", "主动检测已停止", "STOP");
    }

    private void shutdownExtension() {
        try {
            stopAllTasks();
        } finally {
            if (activeExecutor != null) {
                activeExecutor.shutdownNow();
            }
        }
    }

    private void enqueue(IHttpRequestResponse message) {
        capturedQueue.add(message);

        IRequestInfo info = helpers.analyzeRequest(message);
        URL url = info.getUrl();
        String param = info.getParameters().isEmpty() ? "-" : info.getParameters().get(0).getName();

        appendLog(now(), safe(url == null ? null : url.getHost()), safe(url == null ? null : url.getPath()),
                param, "待检测", "请求已收集", "PENDING");
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
            if (!waitIfPausedOrStopped()) {
                appendLog(now(), host, path, parameter.getName(), "控制", "任务被停止", "STOP");
                return;
            }

            String paramName = parameter.getName();
            String value = parameter.getValue();

            IHttpRequestResponse errorProof = runErrorBased(baseMessage, parameter, baseStatus, baseBody, value);
            if (errorProof != null) {
                found = true;
                markVuln(errorProof, "red", "Error-based SQLi confirmed");
                appendLog(now(), host, path, paramName, "报错注入", "数据库报错特征 + 变体", "VULN");
                reportIssue(errorProof, "Error-based SQL Injection", paramName, "High", "Firm");
            }

            BooleanBlindResult blind = runBooleanBlind(baseMessage, parameter, baseResp, value);
            if (blind.vulnerable) {
                found = true;
                markVuln(blind.proofMessage, "yellow", "Boolean blind SQLi confirmed");
                appendLog(now(), host, path, paramName, "盲注", blind.evidence, "VULN");
                reportIssue(blind.proofMessage, "Boolean-based Blind SQL Injection", paramName, "High", "Firm");
            }

            TimeBlindResult timeBlind = runTimeBlind(baseMessage, parameter, value);
            if (timeBlind.vulnerable) {
                found = true;
                markVuln(timeBlind.proofMessage, "orange", "Time blind SQLi confirmed");
                appendLog(now(), host, path, paramName, "时间盲注", timeBlind.evidence, "VULN");
                reportIssue(timeBlind.proofMessage, "Time-based Blind SQL Injection", paramName, "High", "Firm");
            }
        }

        if (!found) {
            appendLog(now(), host, path, "-", "-", "未确认 SQL 注入", "CLEAN");
        }
    }

    private IHttpRequestResponse runErrorBased(IHttpRequestResponse base,
                                               IParameter parameter,
                                               short baseStatus,
                                               String baseBody,
                                               String value) {
        for (String suffix : ERROR_SUFFIXES) {
            if (!waitIfPausedOrStopped()) {
                return null;
            }
            IHttpRequestResponse resp = sendPayload(base, parameter, value + suffix);
            if (resp == null || isLikelyWafBlocked(resp)) {
                continue;
            }
            if (isErrorBased(baseStatus, baseBody, resp.getResponse())) {
                return resp;
            }
        }
        return null;
    }

    private BooleanBlindResult runBooleanBlind(IHttpRequestResponse base,
                                               IParameter parameter,
                                               byte[] baseResp,
                                               String value) {
        int rounds = 3;
        int hit = 0;
        String evidence = "";
        IHttpRequestResponse proof = null;

        for (int i = 0; i < rounds; i++) {
            if (!waitIfPausedOrStopped()) {
                return BooleanBlindResult.notVulnerable();
            }

            for (PayloadPair pair : BOOLEAN_PAIRS) {
                IHttpRequestResponse trueResp = sendPayload(base, parameter, value + pair.trueSuffix);
                IHttpRequestResponse falseResp = sendPayload(base, parameter, value + pair.falseSuffix);
                if (trueResp == null || falseResp == null || isLikelyWafBlocked(trueResp) || isLikelyWafBlocked(falseResp)) {
                    continue;
                }

                SingleBlindCheckResult result = isBooleanBlindLowFp(baseResp, trueResp.getResponse(), falseResp.getResponse());
                if (result.matched) {
                    hit++;
                    proof = falseResp;
                    evidence = "命中 " + hit + "/" + (i + 1) + " payload=" + pair.label + "；" + result.evidence;
                    break;
                }
            }
        }

        return (hit >= 2 && proof != null)
                ? BooleanBlindResult.vulnerable(proof, evidence)
                : BooleanBlindResult.notVulnerable();
    }

    private TimeBlindResult runTimeBlind(IHttpRequestResponse base, IParameter parameter, String value) {
        List<Long> baseline = new ArrayList<Long>();
        for (int i = 0; i < 3; i++) {
            TimedResponse tr = timedSend(base, parameter, value);
            if (tr.response == null) {
                return TimeBlindResult.notVulnerable();
            }
            baseline.add(tr.elapsedMs);
        }

        double mean = mean(baseline);
        double std = stdDev(baseline, mean);
        double threshold = mean + Math.max(2500.0, std * 3.0);

        for (String suffix : TIME_SUFFIXES) {
            int hit = 0;
            long maxDelay = 0;
            IHttpRequestResponse proof = null;

            for (int i = 0; i < 2; i++) {
                TimedResponse delayed = timedSend(base, parameter, value + suffix);
                if (delayed.response == null || isLikelyWafBlocked(delayed.response)) {
                    continue;
                }
                if (delayed.elapsedMs >= threshold) {
                    hit++;
                    proof = delayed.response;
                    if (delayed.elapsedMs > maxDelay) {
                        maxDelay = delayed.elapsedMs;
                    }
                }
            }

            if (hit >= 2 && proof != null) {
                String ev = String.format(Locale.ROOT,
                        "payload=%s 基线%.0fms 波动%.0fms 阈值%.0fms 峰值%dms",
                        suffix, mean, std, threshold, maxDelay);
                return TimeBlindResult.vulnerable(proof, ev);
            }
        }

        return TimeBlindResult.notVulnerable();
    }

    private TimedResponse timedSend(IHttpRequestResponse base, IParameter parameter, String payloadValue) {
        if (!waitIfPausedOrStopped()) {
            return new TimedResponse(null, 0);
        }

        long start = System.currentTimeMillis();
        IHttpRequestResponse response = sendPayload(base, parameter, payloadValue);
        return new TimedResponse(response, System.currentTimeMillis() - start);
    }

    private IHttpRequestResponse sendPayload(IHttpRequestResponse base, IParameter parameter, String payloadValue) {
        if (!waitIfPausedOrStopped()) {
            return null;
        }

        IParameter newParameter = helpers.buildParameter(parameter.getName(), payloadValue, parameter.getType());
        byte[] request = helpers.updateParameter(base.getRequest(), newParameter);
        try {
            return callbacks.makeHttpRequest(base.getHttpService(), request);
        } catch (RuntimeException ex) {
            callbacks.printError("[SQL Hunter] makeHttpRequest failed: " + ex.getMessage());
            return null;
        }
    }

    private boolean waitIfPausedOrStopped() {
        if (stopRequested.get() || Thread.currentThread().isInterrupted()) {
            return false;
        }

        while (paused.get()) {
            synchronized (pauseLock) {
                if (stopRequested.get() || Thread.currentThread().isInterrupted()) {
                    return false;
                }
                try {
                    pauseLock.wait(300L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }

        return !stopRequested.get() && !Thread.currentThread().isInterrupted();
    }

    private boolean isErrorBased(short baseStatus, String baseBody, byte[] response) {
        if (response == null) {
            return false;
        }

        IResponseInfo info = helpers.analyzeResponse(response);
        short status = info.getStatusCode();
        String body = helpers.bytesToString(slice(response, info.getBodyOffset()));

        for (Pattern pattern : ERROR_PATTERNS) {
            if (pattern.matcher(body).find()) {
                return true;
            }
        }

        return status >= 500 && baseStatus < 500 && Math.abs(body.length() - baseBody.length()) > 50;
    }

    private boolean isLikelyWafBlocked(IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) {
            return false;
        }

        IResponseInfo info = helpers.analyzeResponse(response.getResponse());
        short code = info.getStatusCode();
        if (code == 403 || code == 406 || code == 429 || code == 503) {
            return true;
        }

        String body = helpers.bytesToString(slice(response.getResponse(), info.getBodyOffset())).toLowerCase(Locale.ROOT);
        return body.contains("access denied")
                || body.contains("forbidden")
                || body.contains("request blocked")
                || body.contains("waf")
                || body.contains("mod_security")
                || body.contains("cloudflare");
    }

    private SingleBlindCheckResult isBooleanBlindLowFp(byte[] baseResp, byte[] trueResp, byte[] falseResp) {
        if (baseResp == null || trueResp == null || falseResp == null) {
            return SingleBlindCheckResult.noMatch();
        }

        IResponseInfo b = helpers.analyzeResponse(baseResp);
        IResponseInfo t = helpers.analyzeResponse(trueResp);
        IResponseInfo f = helpers.analyzeResponse(falseResp);

        String bBody = normalizeBody(helpers.bytesToString(slice(baseResp, b.getBodyOffset())));
        String tBody = normalizeBody(helpers.bytesToString(slice(trueResp, t.getBodyOffset())));
        String fBody = normalizeBody(helpers.bytesToString(slice(falseResp, f.getBodyOffset())));

        double simTB = similarity(tBody, bBody);
        double simFB = similarity(fBody, bBody);
        double simTF = similarity(tBody, fBody);

        boolean statusSignal = (t.getStatusCode() == b.getStatusCode() && f.getStatusCode() != b.getStatusCode())
                || (t.getStatusCode() != f.getStatusCode());
        boolean simSignal = simTB >= 0.92 && simFB <= 0.85 && (simTB - simFB) >= 0.07;
        boolean polaritySignal = simTF <= 0.88;

        int score = (statusSignal ? 1 : 0) + (simSignal ? 1 : 0) + (polaritySignal ? 1 : 0);
        if (score >= 2) {
            String evidence = String.format(Locale.ROOT,
                    "score=%d status=%s simTB=%.3f simFB=%.3f simTF=%.3f",
                    score, statusSignal, simTB, simFB, simTF);
            return SingleBlindCheckResult.matched(evidence);
        }
        return SingleBlindCheckResult.noMatch();
    }

    private String normalizeBody(String body) {
        if (body == null || body.isEmpty()) {
            return "";
        }

        String normalized = body.length() > 5000 ? body.substring(0, 5000) : body;
        normalized = normalized.replaceAll("\\b\\d{10,}\\b", " ");
        normalized = normalized.replaceAll("[0-9a-fA-F]{8,}", " ");
        normalized = normalized.replaceAll("[0-9]{2,}", " ");
        return normalized.replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
    }

    private double similarity(String a, String b) {
        if (a == null || b == null) {
            return 0.0;
        }
        if (a.equals(b)) {
            return 1.0;
        }
        if (a.isEmpty() || b.isEmpty()) {
            return 0.0;
        }

        int distance = levenshtein(a, b);
        int max = Math.max(a.length(), b.length());
        return max == 0 ? 1.0 : 1.0 - ((double) distance / (double) max);
    }

    private int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] curr = new int[b.length() + 1];

        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }

        for (int i = 1; i <= a.length(); i++) {
            curr[0] = i;
            char ca = a.charAt(i - 1);
            for (int j = 1; j <= b.length(); j++) {
                int cost = ca == b.charAt(j - 1) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = curr;
            curr = tmp;
        }

        return prev[b.length()];
    }

    private double mean(List<Long> samples) {
        if (samples == null || samples.isEmpty()) {
            return 0.0;
        }

        double sum = 0.0;
        for (Long s : samples) {
            sum += s;
        }
        return sum / samples.size();
    }

    private double stdDev(List<Long> samples, double mean) {
        if (samples == null || samples.size() < 2) {
            return 0.0;
        }

        double variance = 0.0;
        for (Long s : samples) {
            double d = s - mean;
            variance += d * d;
        }
        variance = variance / (samples.size() - 1);
        return Math.sqrt(variance);
    }

    private void markVuln(IHttpRequestResponse item, String color, String comment) {
        item.setHighlight(color);
        item.setComment(comment);
    }

    private void reportIssue(IHttpRequestResponse item,
                             String issueName,
                             String paramName,
                             String severity,
                             String confidence) {
        URL url = helpers.analyzeRequest(item).getUrl();
        callbacks.addScanIssue(new CustomScanIssue(
                item.getHttpService(),
                url,
                new IHttpRequestResponse[]{item},
                issueName,
                "Parameter <b>" + paramName + "</b> appears injectable.",
                severity,
                confidence
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
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT);
        df.setTimeZone(TimeZone.getDefault());
        return df.format(new Date());
    }

    private String safe(String value) {
        return value == null ? "-" : value;
    }

    private byte[] slice(byte[] raw, int offset) {
        if (raw == null || offset < 0 || offset >= raw.length) {
            return new byte[0];
        }

        int len = raw.length - offset;
        byte[] out = new byte[len];
        System.arraycopy(raw, offset, out, 0, len);
        return out;
    }

    private static class PayloadPair {
        private final String label;
        private final String trueSuffix;
        private final String falseSuffix;

        private PayloadPair(String label, String trueSuffix, String falseSuffix) {
            this.label = label;
            this.trueSuffix = trueSuffix;
            this.falseSuffix = falseSuffix;
        }
    }

    private static class TimedResponse {
        private final IHttpRequestResponse response;
        private final long elapsedMs;

        private TimedResponse(IHttpRequestResponse response, long elapsedMs) {
            this.response = response;
            this.elapsedMs = elapsedMs;
        }
    }

    private static class SingleBlindCheckResult {
        private final boolean matched;
        private final String evidence;

        private SingleBlindCheckResult(boolean matched, String evidence) {
            this.matched = matched;
            this.evidence = evidence;
        }

        private static SingleBlindCheckResult matched(String evidence) {
            return new SingleBlindCheckResult(true, evidence);
        }

        private static SingleBlindCheckResult noMatch() {
            return new SingleBlindCheckResult(false, "");
        }
    }

    private static class BooleanBlindResult {
        private final boolean vulnerable;
        private final IHttpRequestResponse proofMessage;
        private final String evidence;

        private BooleanBlindResult(boolean vulnerable, IHttpRequestResponse proofMessage, String evidence) {
            this.vulnerable = vulnerable;
            this.proofMessage = proofMessage;
            this.evidence = evidence;
        }

        private static BooleanBlindResult vulnerable(IHttpRequestResponse proofMessage, String evidence) {
            return new BooleanBlindResult(true, proofMessage, evidence);
        }

        private static BooleanBlindResult notVulnerable() {
            return new BooleanBlindResult(false, null, "");
        }
    }

    private static class TimeBlindResult {
        private final boolean vulnerable;
        private final IHttpRequestResponse proofMessage;
        private final String evidence;

        private TimeBlindResult(boolean vulnerable, IHttpRequestResponse proofMessage, String evidence) {
            this.vulnerable = vulnerable;
            this.proofMessage = proofMessage;
            this.evidence = evidence;
        }

        private static TimeBlindResult vulnerable(IHttpRequestResponse proofMessage, String evidence) {
            return new TimeBlindResult(true, proofMessage, evidence);
        }

        private static TimeBlindResult notVulnerable() {
            return new TimeBlindResult(false, null, "");
        }
    }

    private static class CustomScanIssue implements IScanIssue {
        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse[] httpMessages;
        private final String issueName;
        private final String issueDetail;
        private final String severity;
        private final String confidence;

        private CustomScanIssue(IHttpService httpService,
                                URL url,
                                IHttpRequestResponse[] httpMessages,
                                String issueName,
                                String issueDetail,
                                String severity,
                                String confidence) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.issueName = issueName;
            this.issueDetail = issueDetail;
            this.severity = severity;
            this.confidence = confidence;
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
            return confidence;
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
