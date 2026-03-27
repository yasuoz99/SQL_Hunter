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
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel mainPanel;
    private JCheckBox liveCheckBox;
    private JTable logTable;
    private DefaultTableModel tableModel;
    private JButton pauseResumeButton;

    private final List<IHttpRequestResponse> queue = new CopyOnWriteArrayList<IHttpRequestResponse>();
    private final Set<String> processedKeys = new HashSet<String>();
    private final List<Future<?>> runningTasks = new CopyOnWriteArrayList<Future<?>>();

    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private final Object pauseLock = new Object();
    private ExecutorService activeExecutor;

    private static final String[] COLUMNS = new String[]{"时间", "主机", "路径", "参数", "类型", "证据", "状态"};

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.activeExecutor = Executors.newFixedThreadPool(2);

        callbacks.setExtensionName("SQL Hunter (Java8)");
        buildUi();

        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.addSuiteTab(this);
        callbacks.registerExtensionStateListener(() -> {
            try {
                stopAllTasks();
            } finally {
                if (activeExecutor != null) {
                    activeExecutor.shutdownNow();
                }
            }
        });

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
                submitActiveCheck(item);
                JOptionPane.showMessageDialog(mainPanel, "已提交主动检测任务");
                return;
            }
        }

        JOptionPane.showMessageDialog(mainPanel, "未找到对应请求，请使用右键 Send to SQL Hunter");
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
        Future<?> future = activeExecutor.submit(() -> {
            try {
                runActiveChecks(item);
            } finally {
                runningTasks.removeIf(f -> f.isDone() || f.isCancelled());
            }
        });
        runningTasks.add(future);
    }

    private void stopAllTasks() {
        stopRequested.set(true);
        paused.set(false);
        synchronized (pauseLock) {
            pauseLock.notifyAll();
        }

        for (Future<?> future : runningTasks) {
            future.cancel(true);
        }
        runningTasks.clear();
        appendLog(now(), "-", "-", "-", "控制", "主动检测已停止", "STOP");
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
            if (!waitIfPausedOrStopped()) {
                appendLog(now(), host, path, parameter.getName(), "控制", "任务被停止", "STOP");
                return;
            }

            String name = parameter.getName();
            String value = parameter.getValue();

            IHttpRequestResponse errorProof = runErrorBasedWithBypass(baseMessage, parameter, baseStatus, baseBody, value);
            if (errorProof != null) {
                found = true;
                markVuln(errorProof, "red", "Error-based SQLi confirmed");
                appendLog(now(), host, path, name, "报错注入", "发现数据库报错特征（含绕WAF变体）", "VULN");
                reportIssue(errorProof, "Error-based SQL Injection", name, "High", "Firm");
            }

            BooleanBlindResult blindResult = runBooleanBlindWithVoting(baseMessage, parameter, baseResp, value);
            if (blindResult.vulnerable) {
                found = true;
                markVuln(blindResult.proofMessage, "yellow", "Boolean blind SQLi confirmed");
                appendLog(now(), host, path, name, "盲注", blindResult.evidence, "VULN");
                reportIssue(blindResult.proofMessage, "Boolean-based Blind SQL Injection", name, "High", "Firm");
            }

            TimeBlindResult timeResult = runTimeBlindRobust(baseMessage, parameter, value);
            if (timeResult.vulnerable) {
                found = true;
                markVuln(timeResult.proofMessage, "orange", "Time blind SQLi confirmed");
                appendLog(now(), host, path, name, "时间盲注", timeResult.evidence, "VULN");
                reportIssue(timeResult.proofMessage, "Time-based Blind SQL Injection", name, "High", "Firm");
            }
        }

        if (!found) {
            appendLog(now(), host, path, "-", "-", "未确认 SQL 注入", "CLEAN");
        }
    }

    private IHttpRequestResponse runErrorBasedWithBypass(IHttpRequestResponse baseMessage,
                                                         IParameter parameter,
                                                         short baseStatus,
                                                         String baseBody,
                                                         String value) {
        for (String suffix : buildErrorPayloadSuffixes()) {
            if (!waitIfPausedOrStopped()) {
                return null;
            }
            IHttpRequestResponse errorResp = sendPayload(baseMessage, parameter, value + suffix);
            if (isLikelyWafBlocked(errorResp)) {
                continue;
            }
            if (errorResp != null && isErrorBased(baseStatus, baseBody, errorResp.getResponse())) {
                return errorResp;
            }
        }
        return null;
    }

    private BooleanBlindResult runBooleanBlindWithVoting(IHttpRequestResponse baseMessage,
                                                          IParameter parameter,
                                                          byte[] baseResp,
                                                          String value) {
        int rounds = 3;
        int hit = 0;
        String bestEvidence = "";
        IHttpRequestResponse proof = null;
        List<PayloadPair> pairs = buildBooleanPayloadPairs();

        for (int i = 0; i < rounds; i++) {
            if (!waitIfPausedOrStopped()) {
                return BooleanBlindResult.notVulnerable();
            }

            for (PayloadPair pair : pairs) {
                IHttpRequestResponse trueResp = sendPayload(baseMessage, parameter, value + pair.trueSuffix);
                IHttpRequestResponse falseResp = sendPayload(baseMessage, parameter, value + pair.falseSuffix);
                if (trueResp == null || falseResp == null) {
                    continue;
                }
                if (isLikelyWafBlocked(trueResp) || isLikelyWafBlocked(falseResp)) {
                    continue;
                }

                SingleBlindCheckResult single = isBooleanBlindLowFp(baseResp, trueResp.getResponse(), falseResp.getResponse());
                if (single.matched) {
                    hit++;
                    proof = falseResp;
                    bestEvidence = "投票命中 " + hit + "/" + (i + 1) + "；payload=" + pair.label + "；" + single.evidence;
                    break;
                }
            }
        }

        if (hit >= 2 && proof != null) {
            return BooleanBlindResult.vulnerable(proof, bestEvidence);
        }
        return BooleanBlindResult.notVulnerable();
    }

    private TimeBlindResult runTimeBlindRobust(IHttpRequestResponse baseMessage, IParameter parameter, String value) {
        List<Long> baseline = new ArrayList<Long>();
        for (int i = 0; i < 3; i++) {
            if (!waitIfPausedOrStopped()) {
                return TimeBlindResult.notVulnerable();
            }
            TimedResponse tr = timedSend(baseMessage, parameter, value);
            if (tr.response == null) {
                return TimeBlindResult.notVulnerable();
            }
            baseline.add(tr.elapsedMs);
        }

        double mean = mean(baseline);
        double std = stdDev(baseline, mean);
        double dynamicThreshold = mean + Math.max(2500.0, std * 3.0);

        int delayedHits = 0;
        long maxDelay = 0;
        IHttpRequestResponse proof = null;

        for (String suffix : buildTimePayloadSuffixes()) {
            int localHits = 0;
            long localMaxDelay = 0;
            IHttpRequestResponse localProof = null;
            for (int i = 0; i < 2; i++) {
                if (!waitIfPausedOrStopped()) {
                    return TimeBlindResult.notVulnerable();
                }
                TimedResponse delayed = timedSend(baseMessage, parameter, value + suffix);
                if (delayed.response == null || isLikelyWafBlocked(delayed.response)) {
                    continue;
                }
                if (delayed.elapsedMs >= dynamicThreshold) {
                    localHits++;
                    localProof = delayed.response;
                    if (delayed.elapsedMs > localMaxDelay) {
                        localMaxDelay = delayed.elapsedMs;
                    }
                }
            }
            if (localHits >= 2 && localProof != null) {
                delayedHits = localHits;
                maxDelay = localMaxDelay;
                proof = localProof;
                break;
            }
        }

        if (delayedHits >= 2 && proof != null) {
            String ev = String.format(Locale.ROOT,
                    "基线均值 %.0fms，波动 %.0fms，阈值 %.0fms，延时峰值 %dms",
                    mean, std, dynamicThreshold, maxDelay);
            return TimeBlindResult.vulnerable(proof, ev);
        }

        return TimeBlindResult.notVulnerable();
    }

    private List<PayloadPair> buildBooleanPayloadPairs() {
        List<PayloadPair> pairs = new ArrayList<PayloadPair>();
        pairs.add(new PayloadPair("basic-and", "' AND '1'='1", "' AND '1'='2"));
        pairs.add(new PayloadPair("inline-comment", "'/**/AND/**/'1'='1", "'/**/AND/**/'1'='2"));
        pairs.add(new PayloadPair("or-comment", "' OR 1=1-- ", "' OR 1=2-- "));
        pairs.add(new PayloadPair("close-paren", "') OR ('1'='1", "') OR ('1'='2"));
        return pairs;
    }

    private List<String> buildTimePayloadSuffixes() {
        List<String> payloads = new ArrayList<String>();
        payloads.add("'; WAITFOR DELAY '0:0:5'--");
        payloads.add("';WAITFOR/**/DELAY/**/'0:0:5'--");
        payloads.add("' AND SLEEP(5)-- ");
        payloads.add("'||pg_sleep(5)--");
        return payloads;
    }

    private List<String> buildErrorPayloadSuffixes() {
        List<String> payloads = new ArrayList<String>();
        payloads.add("'");
        payloads.add("\"");
        payloads.add("'/**/");
        payloads.add("'))");
        return payloads;
    }

    private TimedResponse timedSend(IHttpRequestResponse base, IParameter parameter, String payloadValue) {
        long start = System.currentTimeMillis();
        IHttpRequestResponse response = sendPayload(base, parameter, payloadValue);
        long elapsed = System.currentTimeMillis() - start;
        return new TimedResponse(response, elapsed);
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

        short bStatus = b.getStatusCode();
        short tStatus = t.getStatusCode();
        short fStatus = f.getStatusCode();

        String bBody = helpers.bytesToString(slice(baseResp, b.getBodyOffset()));
        String tBody = helpers.bytesToString(slice(trueResp, t.getBodyOffset()));
        String fBody = helpers.bytesToString(slice(falseResp, f.getBodyOffset()));

        String bNorm = normalizeBody(bBody);
        String tNorm = normalizeBody(tBody);
        String fNorm = normalizeBody(fBody);

        double simTB = similarity(tNorm, bNorm);
        double simFB = similarity(fNorm, bNorm);
        double simTF = similarity(tNorm, fNorm);

        boolean statusSignal = (tStatus == bStatus && fStatus != bStatus) || (tStatus != fStatus);
        boolean similaritySignal = simTB >= 0.92 && simFB <= 0.85 && (simTB - simFB) >= 0.07;
        boolean polaritySignal = simTF <= 0.88;

        int score = (statusSignal ? 1 : 0) + (similaritySignal ? 1 : 0) + (polaritySignal ? 1 : 0);
        if (score >= 2) {
            String evidence = String.format(Locale.ROOT,
                    "score=%d, status=%s, sim(true/base)=%.3f, sim(false/base)=%.3f, sim(true/false)=%.3f",
                    score, statusSignal, simTB, simFB, simTF);
            return SingleBlindCheckResult.matched(evidence);
        }

        return SingleBlindCheckResult.noMatch();
    }

    private String normalizeBody(String body) {
        if (body == null || body.isEmpty()) {
            return "";
        }

        String normalized = body;
        if (normalized.length() > 5000) {
            normalized = normalized.substring(0, 5000);
        }

        normalized = normalized.replaceAll("\\b\\d{10,}\\b", " ");
        normalized = normalized.replaceAll("[0-9a-fA-F]{8,}", " ");
        normalized = normalized.replaceAll("[0-9]{2,}", " ");
        normalized = normalized.replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
        return normalized;
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
        if (max == 0) {
            return 1.0;
        }
        return 1.0 - ((double) distance / (double) max);
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
                int cost = (ca == b.charAt(j - 1)) ? 0 : 1;
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
        return sum / (double) samples.size();
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
        variance = variance / (double) (samples.size() - 1);
        return Math.sqrt(variance);
    }

    private void markVuln(IHttpRequestResponse item, String color, String comment) {
        item.setHighlight(color);
        item.setComment(comment);
    }

    private void reportIssue(IHttpRequestResponse item, String issueName, String paramName, String severity, String confidence) {
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

    private static class TimedResponse {
        private final IHttpRequestResponse response;
        private final long elapsedMs;

        private TimedResponse(IHttpRequestResponse response, long elapsedMs) {
            this.response = response;
            this.elapsedMs = elapsedMs;
        }
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

        public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages,
                               String issueName, String issueDetail, String severity, String confidence) {
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
