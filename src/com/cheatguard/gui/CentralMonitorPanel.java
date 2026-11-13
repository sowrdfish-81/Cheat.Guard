package com.cheatguard.gui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.security.SecureRandom;
import java.util.concurrent.CopyOnWriteArrayList;
import com.cheatguard.watchdog.CentralAuth;
import com.cheatguard.watchdog.CentralReporter;
import com.cheatguard.watchdog.CentralTls;

// ============================================================================
// SHARED FILE OWNERSHIP
// Muhit  : lockdown/security state shown by this panel.
// Rohan  : central connection, event intake, ranking data and alert counts.
// Rafa   : layout, table rendering, highlighting, controls and UX behavior.
// Keep changes inside the matching section below and coordinate cross-section
// changes before merging.
// ============================================================================

/**
 * The invigilator's central screen, organised the way an invigilator thinks:
 *
 * <p>STUDENT LIST - one row per exam PC, sorted so that anyone who triggered a
 * red alert sits at the TOP marked SUSPICIOUS (amber). Clicking a row opens that
 * student's FULL log; Back returns to the list. The invigilator reads the log
 * and decides - a red flag means the student TRIED something, and Cheat.Guard
 * can be wrong - so the row keeps saying SUSPICIOUS until the invigilator marks
 * it "Cheat confirmed" or "Cleared". Verdicts are recorded in the CSV too.
 */
public class CentralMonitorPanel extends JPanel {

    // ============================ Rohan: data ===============================
    // Student records, event intake, sorting and alert-ranking state.

    private static final int CENTRAL_TCP_PORT = 47821;
    private static final String FIREWALL_RULE_NAME = "Cheat.Guard Monitor";
    private static final int MAX_PENDING_BYTES = 128 * 1024;
    private static final int MAX_STUDENTS = 500;
    private static final int MAX_EVENTS_PER_STUDENT = 2000;

    /** One exam PC + student and everything they did. */
    private static final class StudentRecord {
        final String pc;
        String student = "—";
        String course = "—";
        final List<String[]> events = new ArrayList<>();   // {time, level, event}
        boolean suspicious;
        String verdict = "";                                // CHEAT CONFIRMED / CLEARED / ""
        boolean sessionEnded;
        long lastActivity;
        long lastRedAt;

        StudentRecord(String pc) { this.pc = pc; }

        String status() {
            if ("CHEAT CONFIRMED".equals(verdict)) return "CHEAT CONFIRMED";
            if (suspicious) return "SUSPICIOUS";
            if ("CLEARED".equals(verdict)) return "CLEARED";
            if (sessionEnded) return "OFFLINE";
            return "ACTIVE";
        }
    }

    private final Map<String, StudentRecord> students = new LinkedHashMap<>(); // key = student@pc

    private final DefaultTableModel studentModel = new DefaultTableModel(
            new Object[]{"Student ID", "PC", "Course", "Status", "Red flags", "Last seen"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };

    // ============================ Rafa: presentation ========================
    // Swing layout, table columns, row highlighting and invigilator controls.
    private final JTable studentTable = new JTable(studentModel);

    private final DefaultTableModel eventModel = new DefaultTableModel(
            new Object[]{"Time", "Level", "Event"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable eventTable = new JTable(eventModel);

    private final JLabel statusLabel = new JLabel("Monitor stopped.");
    private final JLabel lanIpLabel = new JLabel();
    private final JLabel activeCodeLabel = new JLabel();
    private final JLabel counters = new JLabel("PCs: 0   Alerts: 0");
    private final JLabel detailTitle = new JLabel();
    private StudentRecord detailStudent;
    private String selectedKey;
    private boolean showingDetail;

    private final java.util.concurrent.atomic.AtomicLong alertCount = new java.util.concurrent.atomic.AtomicLong();
    private final CopyOnWriteArrayList<java.io.Closeable> closables = new CopyOnWriteArrayList<>();

    private volatile boolean running;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private volatile Thread beaconThread;
    private volatile String examCode = "";
    private volatile boolean firewallRuleAdded;
    private BufferedWriter csvWriter;

    private JPanel centerHost;
    private JPanel listPanel;
    private JPanel detailPanel;
    private JButton markCheatBtn;
    private JButton markClearedBtn;
    private JButton newCodeButton;
    private final JTextField codeField = new JTextField();
    private final Timer tableRefreshTimer;

    public CentralMonitorPanel(Runnable onBack) {
        setLayout(new BorderLayout(14, 14));
        setBackground(UITheme.BG_DARK);
        setBorder(UITheme.padding(20, 22, 20, 22));

        // ------------------------------------------------------------- header
        JLabel title = UITheme.title("Invigilator central monitor");
        JLabel subtitle = UITheme.muted("Live student connections and alerts.");
        JPanel titles = new JPanel();
        titles.setLayout(new BoxLayout(titles, BoxLayout.Y_AXIS));
        titles.setOpaque(false);
        titles.add(title);
        titles.add(Box.createVerticalStrut(4));
        titles.add(subtitle);

        JButton back = UITheme.ghost("Back");
        back.addActionListener(e -> {
            onBack.run();
        });
        JPanel header = new JPanel(new BorderLayout(12, 0));
        header.setOpaque(false);
        header.add(titles, BorderLayout.WEST);
        header.add(back, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);

        // -------------------------------------------------------- list panel
        studentTable.setRowHeight(30);
        studentTable.setFont(UITheme.FONT_BODY);
        studentTable.getTableHeader().setFont(UITheme.FONT_SECTION);
        studentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        studentTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        studentTable.setBackground(new Color(0x0F131C));
        studentTable.setForeground(UITheme.TEXT_WHITE);
        studentTable.getTableHeader().setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                c.setBackground(new Color(0x141927));
                c.setForeground(UITheme.TEXT_MUTED);
                c.setFont(UITheme.FONT_SECTION);
                ((JComponent) c).setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
                return c;
            }
        });
        int[] studentWidths = {190, 150, 150, 170, 95, 130};
        for (int i = 0; i < studentWidths.length && i < studentTable.getColumnCount(); i++) {
            studentTable.getColumnModel().getColumn(i).setPreferredWidth(studentWidths[i]);
            studentTable.getColumnModel().getColumn(i).setMinWidth(70);
        }
        studentTable.getTableHeader().setReorderingAllowed(false);
        studentTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                c.setBackground(new Color(0x0F131C));
                String status = row < t.getModel().getRowCount()
                        ? String.valueOf(t.getModel().getValueAt(row, 3)) : "";
                if ("CHEAT CONFIRMED".equals(status)) {
                    c.setBackground(sel ? new Color(0x7A2934) : new Color(0x3A1820));
                    c.setForeground(new Color(0xFFB4BA));
                    c.setFont(UITheme.FONT_SECTION);
                } else if ("SUSPICIOUS".equals(status)) {
                    c.setBackground(sel ? new Color(0x72551A) : new Color(0x302512));
                    c.setForeground(new Color(0xFFF0A8));
                    c.setFont(UITheme.FONT_SECTION);
                } else if ("CLEARED".equals(status)) {
                    c.setForeground(UITheme.ACCENT_TEAL);
                    c.setFont(UITheme.FONT_BODY);
                } else if ("OFFLINE".equals(status)) {
                    c.setForeground(UITheme.TEXT_MUTED);
                    c.setFont(UITheme.FONT_BODY);
                } else {
                    c.setForeground(UITheme.TEXT_WHITE);
                    c.setFont(UITheme.FONT_BODY);
                }
                return c;
            }
        });
        studentTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                openDetailOfSelected();
            }
        });
        JScrollPane studentScroll = UITheme.scroll(studentTable);
        studentScroll.getViewport().setBackground(UITheme.BG_INPUT);

        codeField.setFont(UITheme.FONT_SECTION);
        codeField.setForeground(UITheme.TEXT_WHITE);
        codeField.setBackground(new Color(0x0F131C));
        codeField.setCaretColor(UITheme.TEXT_WHITE);
        codeField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x2A3242), 1),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)));
        codeField.setPreferredSize(new Dimension(150, 34));
        codeField.setText(randomCode());
        newCodeButton = UITheme.ghost("New code");
        newCodeButton.addActionListener(e -> {
            if (!running) codeField.setText(randomCode());
        });
        JButton start = UITheme.primary("Start monitor");
        start.addActionListener(e -> startMonitor());
        JButton stop = UITheme.ghost("Stop");
        stop.addActionListener(e -> stopMonitor());
        JButton removeChecked = UITheme.ghost("Remove checked");
        removeChecked.setToolTipText("Remove rows marked CLEARED or CHEAT CONFIRMED");
        removeChecked.addActionListener(e -> removeStudentRows(false));
        JButton removeInactive = UITheme.ghost("Remove offline");
        removeInactive.setToolTipText("Remove all students whose session has ended");
        removeInactive.addActionListener(e -> removeStudentRows(true));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        controls.setOpaque(false);
        controls.add(new JLabel("Exam code:"));
        controls.add(codeField);
        controls.add(newCodeButton);
        controls.add(start);
        controls.add(stop);
        controls.add(removeChecked);
        controls.add(removeInactive);
        counters.setFont(UITheme.FONT_SECTION);
        JPanel controlsRow = new JPanel(new BorderLayout(10, 0));
        controlsRow.setOpaque(false);
        controlsRow.add(controls, BorderLayout.WEST);
        controlsRow.add(counters, BorderLayout.EAST);

        statusLabel.setFont(UITheme.FONT_BODY);
        configureCopyLabel(lanIpLabel, "LAN IP: ");
        configureCopyLabel(activeCodeLabel, "Exam code: ");
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 0));
        statusRow.setOpaque(false);
        statusRow.add(statusLabel);
        statusRow.add(lanIpLabel);
        statusRow.add(activeCodeLabel);

        JPanel listCard = UITheme.card();
        listCard.setLayout(new BorderLayout(10, 12));
        JPanel top = new JPanel(new BorderLayout(0, 12));
        top.setOpaque(false);
        top.add(controlsRow, BorderLayout.NORTH);
        top.add(statusRow, BorderLayout.SOUTH);
        listCard.add(top, BorderLayout.NORTH);
        listCard.add(studentScroll, BorderLayout.CENTER);

        listPanel = new JPanel(new BorderLayout());
        listPanel.setOpaque(false);
        listPanel.add(listCard, BorderLayout.CENTER);

        // ------------------------------------------------------ detail panel
        JButton backToList = UITheme.secondary("← Back to students");
        backToList.addActionListener(e -> showList());
        markCheatBtn = new JButton("Mark: cheat confirmed");
        markCheatBtn.setBackground(new Color(0x3A1C23));
        markCheatBtn.setForeground(new Color(0xFF9CA5));
        markCheatBtn.setFocusPainted(false);
        markCheatBtn.setOpaque(true);
        markCheatBtn.setBorderPainted(false);
        markCheatBtn.setFont(UITheme.FONT_SECTION);
        markClearedBtn = UITheme.secondary("Mark: cleared");
        // Verdict buttons: without these listeners the whole verdict workflow
        // (applyVerdict -> CSV row -> CHEAT CONFIRMED ranking) was unreachable.
        markCheatBtn.addActionListener(e -> applyVerdict("CHEAT CONFIRMED"));
        markClearedBtn.addActionListener(e -> applyVerdict("CLEARED"));
        JPanel verdicts = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        verdicts.setOpaque(false);
        verdicts.add(markClearedBtn);
        verdicts.add(markCheatBtn);

        detailTitle.setFont(UITheme.FONT_SECTION);
        detailTitle.setForeground(UITheme.TEXT_WHITE);

        JPanel detailHeader = new JPanel(new BorderLayout(10, 0));
        detailHeader.setOpaque(false);
        detailHeader.add(backToList, BorderLayout.WEST);
        detailHeader.add(verdicts, BorderLayout.EAST);

        eventTable.setRowHeight(26);
        eventTable.setFont(UITheme.FONT_BODY);
        eventTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        eventTable.setBackground(new Color(0x0F131C));
        eventTable.setForeground(UITheme.TEXT_WHITE);
        eventTable.getTableHeader().setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                c.setBackground(new Color(0x141927));
                c.setForeground(UITheme.TEXT_MUTED);
                c.setFont(UITheme.FONT_SECTION);
                ((JComponent) c).setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
                return c;
            }
        });
        int[] eventWidths = {110, 110};
        for (int i = 0; i < eventWidths.length && i < eventTable.getColumnCount(); i++) {
            eventTable.getColumnModel().getColumn(i).setPreferredWidth(eventWidths[i]);
            eventTable.getColumnModel().getColumn(i).setMinWidth(80);
        }
        eventTable.getTableHeader().setReorderingAllowed(false);
        JScrollPane eventScroll = UITheme.scroll(eventTable);
        eventScroll.getViewport().setBackground(UITheme.BG_INPUT);

        JPanel detailCard = UITheme.card();
        detailCard.setLayout(new BorderLayout(10, 10));
        detailCard.add(detailHeader, BorderLayout.NORTH);
        JPanel detailCenter = new JPanel(new BorderLayout(0, 12));
        detailCenter.setOpaque(false);
        detailCenter.add(detailTitle, BorderLayout.NORTH);
        detailCenter.add(eventScroll, BorderLayout.CENTER);
        detailCard.add(detailCenter, BorderLayout.CENTER);

        detailPanel = new JPanel(new BorderLayout());
        detailPanel.setOpaque(false);
        detailPanel.add(detailCard, BorderLayout.CENTER);

        // host + start screen
        centerHost = new JPanel(new BorderLayout());
        centerHost.setOpaque(false);
        centerHost.add(listPanel, BorderLayout.CENTER);

        add(centerHost, BorderLayout.CENTER);

        // A SESSION_END can arrive on a worker thread while the table is being
        // viewed. Refresh on the EDT so the row changes to OFFLINE immediately.
        tableRefreshTimer = new Timer(1000, e -> {
            if (!showingDetail) rebuildStudentTable();
        });
        tableRefreshTimer.setRepeats(true);
        tableRefreshTimer.start();
    }

    // ------------------------------------------------------------- lifecycle --

    private synchronized void startMonitor() {
        if (running) return;
        String code = codeField.getText().trim();
        if (!code.matches("[A-Za-z0-9]{3,6}")) {
            statusLabel.setText("The exam code needs 3-6 letters or numbers.");
            statusLabel.setForeground(UITheme.ACCENT_RED);
            return;
        }
        examCode = code;
        boolean certificateRotated = false;
        try {
            statusLabel.setText("Requesting administrator approval for the monitor firewall...");
            statusLabel.setForeground(UITheme.WARN);
            openFirewall();
            ensureFirewallShutdownHook();
            // Refresh the certificate when the network changed since it was
            // issued: without this, every student connection would fail
            // certificate validation after a hotspot/subnet move.
            if (!CentralTls.plaintextDevModeEnabled()) {
                certificateRotated = CentralTls.ensureCurrentIpsCovered();
            }
            serverSocket = CentralTls.openServerSocket(CENTRAL_TCP_PORT);
            openCsv();
            running = true;
            acceptThread = new Thread(this::acceptLoop, "CheatGuard-CentralAccept");
            acceptThread.setDaemon(true);
            acceptThread.start();
            startBeacon();
            newCodeButton.setEnabled(false);
            codeField.setEditable(false);
            statusLabel.setText("Students must be on the SAME Wi-Fi/network as you.");
            statusLabel.setForeground(UITheme.ACCENT_TEAL);
            setCopyValue(lanIpLabel, "LAN IP: ", String.join(", ", lanIps()));
            setCopyValue(activeCodeLabel, "Exam code: ", code);
            if (certificateRotated) {
                JOptionPane.showMessageDialog(this,
                        "The network changed, so the monitor certificate was regenerated.\n"
                                + "Student PCs re-pair automatically via the beacon.",
                        "Certificate regenerated", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            statusLabel.setText("Could not start: " + e.getMessage() + " (port already in use?)");
            statusLabel.setForeground(UITheme.ACCENT_RED);
            // Clean up a partially opened firewall/socket/CSV without replacing
            // the actionable startup error with the generic "Monitor stopped".
            cleanupMonitorResources();
            newCodeButton.setEnabled(true);
            codeField.setEditable(true);
        }
    }

    private synchronized void stopMonitor() {
        running = false;
        cleanupMonitorResources();
        newCodeButton.setEnabled(true);
        codeField.setEditable(true);
        statusLabel.setText("Monitor stopped.");
        statusLabel.setForeground(UITheme.TEXT_MUTED);
    }

    /** A teal label that copies its value to the clipboard when clicked. */
    private void configureCopyLabel(JLabel label, String prefix) {
        label.setFont(UITheme.FONT_SECTION);
        label.setForeground(UITheme.ACCENT_TEAL);
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        label.setToolTipText("Click to copy");
        label.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                String value = label.getClientProperty("copyValue") instanceof String s ? s : "";
                if (value.isBlank()) return;
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(value), null);
                label.setText(prefix + value + "  (Copied)");
                Timer timer = new Timer(1400, ev -> label.setText(prefix + value));
                timer.setRepeats(false);
                timer.start();
            }
        });
    }

    private void setCopyValue(JLabel label, String prefix, String value) {
        label.putClientProperty("copyValue", value == null ? "" : value);
        label.setText(prefix + (value == null ? "" : value));
    }

    private void cleanupMonitorResources() {
        running = false;
        stopBeacon();
        setCopyValue(lanIpLabel, "LAN IP: ", "");
        setCopyValue(activeCodeLabel, "Exam code: ", "");
        try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        serverSocket = null;
        for (java.io.Closeable c : closables) {
            try { c.close(); } catch (Exception ignored) {}
        }
        closables.clear();
        try { if (csvWriter != null) csvWriter.close(); } catch (Exception ignored) {}
        csvWriter = null;
        closeFirewall();
    }

    // ----------------------------------------------------------- server I/O --

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                closables.add(socket);
                Thread t = new Thread(() -> readClient(socket), "CheatGuard-CentralClient");
                t.setDaemon(true);
                t.start();
            } catch (Exception e) {
                if (running) sleepQuiet(300);
                else return;
            }
        }
    }

    private void readClient(Socket socket) {
        ConnectionState connection = null;
        try (socket; InputStream in = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {
            // Unauthenticated peers must not pin a reader thread forever: the
            // firewall rule opens this port to the whole subnet, and a connect-
            // and-hold client would otherwise hold its thread (and nonce)
            // indefinitely.
            socket.setSoTimeout(30000);
            String nonce = CentralAuth.newNonce();
            out.write(("CHALLENGE@@@" + nonce + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            // Decode through a reader instead of per-chunk new String(): a
            // multi-byte UTF-8 character split across two read() chunks used to
            // arrive corrupted (garbled rows, or one student split into two).
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8));
            connection = new ConnectionState(nonce);
            String line;
            while (running && (line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.length() > MAX_PENDING_BYTES) return;
                if (!connection.authenticated && line.startsWith("AUTH@@@")) {
                    // The client may idle for the whole exam now; only the
                    // pre-auth handshake is time-boxed.
                    socket.setSoTimeout(0);
                }
                handleLine(line, socket, out, connection);
            }
        } catch (Exception ignored) {
            // the student PC disconnected; its rows stay on screen
        } finally {
            closables.remove(socket);
            if (connection != null && connection.authenticated && !connection.sessionEnded) {
                markConnectionOffline(connection.recordKey);
            }
        }
    }

    /** Line format: millis@@@pc@@@student@@@course@@@severity@@@type@@@message@@@display */
    private void handleLine(String line, Socket socket, OutputStream out, ConnectionState connection) {
        String[] p = line.split("@@@", 8);
        String time;
        String pc;
        String student;
        String course;
        String severity;
        String event;
        if ("HELLO".equals(p[0]) && p.length >= 4) {
            if (connection.helloReceived || connection.authenticated) return;
            connection.pc = p[1].trim();
            connection.student = p[2].trim();
            connection.course = p[3].trim();
            connection.helloReceived = true;
            connection.recordKey = keyOf(connection.pc, connection.student);
            return;
        } else if ("AUTH".equals(p[0]) && p.length >= 2) {
            if (!connection.helloReceived || connection.authenticated
                    || !CentralAuth.constantTimeEquals(
                    CentralAuth.response(examCode, connection.nonce, connection.pc,
                            connection.student, connection.course), p[1].trim())) {
                // Tell the student PC WHY the connection died: without an
                // acknowledgement a rejected client silently retried forever,
                // discarding every queued event (a mistyped exam code looked
                // like a dead monitor).
                try {
                    out.write(("DENIED\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } catch (Exception ignored) {}
                try { socket.close(); } catch (Exception ignored) {}
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Rejected an unauthenticated central connection.");
                    statusLabel.setForeground(UITheme.WARN);
                });
                return;
            }
            connection.authenticated = true;
            try {
                out.write(("OK\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            } catch (Exception ignored) {}
            time = new SimpleDateFormat("HH:mm:ss").format(new Date());
            pc = connection.pc;
            student = connection.student;
            course = connection.course;
            severity = "INFO";
            event = "Session joined with authenticated challenge response";
        } else if (p.length >= 7) {
            if (!connection.authenticated) return;
            try {
                time = new SimpleDateFormat("HH:mm:ss").format(new Date(Long.parseLong(p[0])));
            } catch (Exception e) {
                time = new SimpleDateFormat("HH:mm:ss").format(new Date());
            }
            pc = p[1].trim();
            student = p[2].trim();
            course = p[3].trim();
            severity = p[4].trim();
            String type = p[5].trim();
            String message = p.length >= 8 ? p[7].trim() : p[6].trim();
            event = message.startsWith(type + ":") ? message : type + ": " + message;
            final boolean sessionEnd = "SESSION_END".equalsIgnoreCase(type);
            // Cap retained event text: without a per-event byte budget, an
            // authenticated spamming client could retain ~136 KB x 2000 events
            // per student record and push the invigilator toward OOM.
            if (event.length() > 4096) event = event.substring(0, 4096) + " …";
            connection.sessionEnded = sessionEnd;
        } else {
            return;
        }

        StudentRecord rec = recordFor(pc, student, course);
        boolean red = "CRITICAL".equalsIgnoreCase(severity) || "WARNING".equalsIgnoreCase(severity);
        synchronized (rec) {
            if (!"—".equals(student)) rec.student = student;
            if (!"—".equals(course)) rec.course = course;
            if (rec.events.size() >= MAX_EVENTS_PER_STUDENT) rec.events.remove(0);
            rec.events.add(new String[]{time, rowSeverity(severity, red), event});
            rec.lastActivity = System.currentTimeMillis();
            if (connection.sessionEnded) rec.sessionEnded = true;
            if (red) {
                rec.suspicious = true;
                rec.lastRedAt = System.currentTimeMillis();
            }
        }
        if (red) alertCount.incrementAndGet();

        final String fTime = time, fSev = rowSeverity(severity, red), fEvent = event;
        final String fKey = keyOf(pc, student);
        SwingUtilities.invokeLater(() -> {
            if (showingDetail && detailStudent != null
                    && fKey.equals(keyOf(detailStudent.pc, detailStudent.student))) {
                eventModel.addRow(new Object[]{fTime, fSev, fEvent});
                if (eventModel.getRowCount() > MAX_EVENTS_PER_STUDENT) eventModel.removeRow(0);
            }
            rebuildStudentTable();
            counters.setText("PCs: " + students.size() + "   Alerts: " + alertCount.get());
        });
        writeCsv(fTime, pc, student, course, fSev, fEvent);
    }

    private static String rowSeverity(String severity, boolean red) {
        return red ? "RED FLAG" : "NOTICE".equalsIgnoreCase(severity) ? "BLOCKED" : severity;
    }

    private static String keyOf(String pc, String student) {
        return student + "@" + pc;
    }

    private StudentRecord recordFor(String pc, String student, String course) {
        String key = keyOf(pc, student);
        synchronized (students) {
            StudentRecord rec = students.get(key);
            if (rec == null) {
                if (students.size() >= MAX_STUDENTS) {
                    String oldest = students.entrySet().stream()
                            .min(Map.Entry.comparingByValue((a, b) -> Long.compare(a.lastActivity, b.lastActivity)))
                            .map(Map.Entry::getKey).orElse(null);
                    if (oldest != null) students.remove(oldest);
                }
                rec = new StudentRecord(pc);
                if (!"—".equals(student)) rec.student = student;
                if (!"—".equals(course)) rec.course = course;
                students.put(key, rec);
            }
            return rec;
        }
    }

    // -------------------------------------------------------------- detail ----

    private void openDetailOfSelected() {
        int row = studentTable.getSelectedRow();
        if (row < 0 || row >= studentModel.getRowCount()) return;
        String student = String.valueOf(studentModel.getValueAt(row, 0));
        String pc = String.valueOf(studentModel.getValueAt(row, 1));
        StudentRecord rec;
        synchronized (students) {
            rec = students.get(keyOf(pc, student));
        }
        if (rec == null) return;
        synchronized (rec) {
            detailStudent = rec;
            selectedKey = keyOf(pc, student);
            eventModel.setRowCount(0);
            for (String[] ev : rec.events) {
                eventModel.addRow(new Object[]{ev[0], ev[1], ev[2]});
            }
            detailTitle.setText("Student " + rec.student + "  ·  PC " + rec.pc
                    + "  ·  " + rec.course + "  —  " + rec.status());
            detailTitle.setForeground("CHEAT CONFIRMED".equals(rec.verdict) ? new Color(0xFFB4BA)
                    : rec.suspicious ? new Color(0xFFF0A8) : UITheme.ACCENT_TEAL);
            markCheatBtn.setEnabled(!"CHEAT CONFIRMED".equals(rec.verdict));
            markClearedBtn.setEnabled(true);
        }
        showingDetail = true;
        centerHost.removeAll();
        centerHost.add(detailPanel, BorderLayout.CENTER);
        centerHost.revalidate();
        centerHost.repaint();
    }

    private void showList() {
        showingDetail = false;
        detailStudent = null;
        rebuildStudentTable();
        centerHost.removeAll();
        centerHost.add(listPanel, BorderLayout.CENTER);
        centerHost.revalidate();
        centerHost.repaint();
    }

    private void applyVerdict(String verdict) {
        if (detailStudent == null) return;
        synchronized (detailStudent) {
            detailStudent.verdict = verdict;
        }
        writeCsv(new SimpleDateFormat("HH:mm:ss").format(new Date()), detailStudent.pc,
                detailStudent.student, detailStudent.course, "VERDICT",
                "Invigilator marked this student: " + verdict);
        openDetailOfSelected(); // refresh title + buttons
        rebuildStudentTable();
    }

    // ------------------------------------------------------- student table ----

    /** Rebuild the student list: cheat-confirmed first, then suspicious (most
     *  recent red first), then the rest by last activity. */
    private void rebuildStudentTable() {
        List<StudentRecord> sorted;
        synchronized (students) {
            sorted = new ArrayList<>(students.values());
        }
        sorted.sort((a, b) -> {
            int ra = rank(a);
            int rb = rank(b);
            if (ra != rb) return Integer.compare(ra, rb);
            if (ra == 1) {
                int redsA = redFlagCount(a);
                int redsB = redFlagCount(b);
                if (redsA != redsB) return Integer.compare(redsB, redsA);
            }
            return Long.compare(b.lastActivity, a.lastActivity);
        });
        studentModel.setRowCount(0);
        SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
        for (StudentRecord rec : sorted) {
            long reds;
            long seen;
            synchronized (rec) {
                reds = rec.events.stream().filter(ev -> "RED FLAG".equals(ev[1])).count();
                seen = rec.lastActivity;
            }
            studentModel.addRow(new Object[]{
                    rec.student, rec.pc, rec.course, rec.status(), reds,
                    seen == 0 ? "—" : fmt.format(new Date(seen))});
        }
        if (selectedKey != null) {
            for (int i = 0; i < studentModel.getRowCount(); i++) {
                String k = keyOf(String.valueOf(studentModel.getValueAt(i, 1)),
                        String.valueOf(studentModel.getValueAt(i, 0)));
                if (k.equals(selectedKey)) {
                    studentTable.setRowSelectionInterval(i, i);
                    break;
                }
            }
        }
    }

    private static int rank(StudentRecord rec) {
        if ("CHEAT CONFIRMED".equals(rec.verdict)) return 0;
        if (rec.suspicious) return 1;
        return 2;
    }

    private static int redFlagCount(StudentRecord rec) {
        synchronized (rec) {
            int count = 0;
            for (String[] event : rec.events) {
                if (event.length > 1 && "RED FLAG".equals(event[1])) count++;
            }
            return count;
        }
    }

    /** Remove only rows that are no longer actionable, never an active row. */
    private void removeStudentRows(boolean offlineOnly) {
        List<String> removed = new ArrayList<>();
        synchronized (students) {
            students.entrySet().removeIf(entry -> {
                StudentRecord rec = entry.getValue();
                boolean remove = offlineOnly ? rec.sessionEnded
                        : ("CLEARED".equals(rec.verdict) || "CHEAT CONFIRMED".equals(rec.verdict));
                if (remove) removed.add(entry.getKey());
                return remove;
            });
        }
        if (selectedKey != null && removed.contains(selectedKey)) showList();
        rebuildStudentTable();
        counters.setText("PCs: " + students.size() + "   Alerts: " + alertCount.get());
    }

    // ------------------------------------------------------- firewall + csv ----

    private void openFirewall() {
        // Always request an explicit UAC approval so the invigilator can see
        // that the protected monitor firewall setup is actually running. A
        // silently reused rule made failed starts indistinguishable from a
        // successful one during troubleshooting.
        boolean existedBeforeStart = ruleExists();
        if (!existedBeforeStart && !runElevated("netsh.exe", "advfirewall", "firewall", "add", "rule",
                "name=" + FIREWALL_RULE_NAME, "dir=in", "action=allow",
                "protocol=TCP", "localport=" + CENTRAL_TCP_PORT) || !ruleExists()) {
            throw new IllegalStateException("Windows Firewall permission was not granted. Approve the administrator prompt.");
        }
        // Preserve an administrator-managed rule. Only delete a rule that this
        // monitor instance actually created, otherwise Stop/Exit silently
        // removes the user's existing firewall configuration.
        firewallRuleAdded = !existedBeforeStart;
    }

    private static boolean ruleExists() {
        try {
            Process p = new ProcessBuilder("netsh.exe", "advfirewall", "firewall", "show", "rule",
                    "name=" + FIREWALL_RULE_NAME).redirectErrorStream(true).start();
            String output = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            if (!p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
            String normalized = output.toLowerCase(java.util.Locale.ROOT);
            // netsh can return exit code 0 even for "No rules match". Do not
            // treat that as success or the elevated add step is skipped and
            // student PCs cannot reach the listener.
            return p.exitValue() == 0
                    && !normalized.contains("no rules match")
                    && (normalized.contains("rule name")
                        || normalized.contains(FIREWALL_RULE_NAME.toLowerCase(java.util.Locale.ROOT)));
        } catch (Exception ignored) {
            return false;
        }
    }

    private void closeFirewall() {
        if (!firewallRuleAdded) return;
        runElevated("netsh.exe", "advfirewall", "firewall", "delete", "rule",
                "name=" + FIREWALL_RULE_NAME);
        firewallRuleAdded = false;
    }

    /** The invigilator listener must be reachable through Windows Firewall. */
    private static boolean runElevated(String... command) {
        try {
            if (command == null || command.length == 0) return false;
            if (isCurrentProcessElevated()) {
                Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
                p.getInputStream().readAllBytes();
                if (!p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    return false;
                }
                return p.exitValue() == 0;
            }
            StringBuilder args = new StringBuilder("@");
            args.append("(");
            for (int i = 1; i < command.length; i++) {
                if (i > 1) args.append(',');
                args.append("'").append(command[i].replace("'", "''")).append("'");
            }
            args.append(")");
            String ps = "$p=Start-Process -FilePath '" + command[0]
                    + "' -ArgumentList " + args
                    + " -Verb RunAs -WindowStyle Normal -PassThru -Wait; exit $p.ExitCode";
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-Command", ps)
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            if (!p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean isCurrentProcessElevated() {
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command",
                    "(New-Object Security.Principal.WindowsPrincipal("+
                            "[Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("+
                            "[Security.Principal.WindowsBuiltInRole]::Administrator)")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            return p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)
                    && "true".equalsIgnoreCase(out);
        } catch (Exception ignored) {
            return false;
        }
    }


    private static void runQuiet(String... command) {
        try {
            Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) {
        }
    }

    /**
     * The inbound monitor allow rule is persistent. If the invigilator exits the
     * whole app (Exit / window X / update restart) without pressing Back, nothing
     * else removes it — so a JVM shutdown hook deletes the rule whenever it was
     * added and still set.
     */
    private static boolean firewallHookInstalled;

    private void ensureFirewallShutdownHook() {
        synchronized (CentralMonitorPanel.class) {
            if (firewallHookInstalled) return;
            firewallHookInstalled = true;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                if (firewallRuleAdded) closeFirewall();
            } catch (Exception ignored) {
            }
        }, "CheatGuard-CentralFirewallCleanup"));
    }

    private void openCsv() {
        try {
            File dir = new File(System.getProperty("user.home"), "CheatGuard-Central");
            if (!dir.exists()) dir.mkdirs();
            File csvFile = new File(dir, "central-log-"
                    + new SimpleDateFormat("yyyyMMdd").format(new Date()) + ".csv");
            boolean fresh = !csvFile.isFile() || csvFile.length() == 0;
            // Explicit UTF-8 (with BOM so Excel detects it): the platform default
            // on Windows mangled non-ASCII student IDs / course codes, and this
            // CSV is the official audit record. Also: a header row per restart
            // corrupted the day's file — write it only for a fresh file.
            csvWriter = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(csvFile, true), StandardCharsets.UTF_8));
            csvWriter.write(fresh ? "﻿time,pc,student,course,level,event\n"
                    : "");
        } catch (Exception e) {
            csvWriter = null;
        }
    }

    private void writeCsv(String time, String pc, String student, String course, String level, String event) {
        BufferedWriter writer = csvWriter;
        if (writer == null) return;
        try {
            synchronized (this) {
                writer.write(csv(time) + "," + csv(pc) + "," + csv(student) + ","
                        + csv(course) + "," + csv(level) + "," + csv(event) + "\n");
                writer.flush();
            }
        } catch (Exception ignored) {
        }
    }

    private static String csv(String v) {
        String s = v == null ? "" : v.replace("\"", "'").replace("\n", " ").replace("\r", " ");
        // Event fields come from unauthenticated student PCs. A cell starting
        // with = + - or @ executes as a formula when the invigilator opens the
        // CSV in Excel, so neutralize it with a leading apostrophe.
        if (s.startsWith("=") || s.startsWith("+") || s.startsWith("-") || s.startsWith("@")
                || s.startsWith("\t")) {
            s = "'" + s;
        }
        return "\"" + s + "\"";
    }

    /**
     * This machine's REAL LAN IP - the address students must type. Virtual
     * adapters (WSL, Hyper-V, VirtualBox, VPN tunnels) also hold site-local
     * addresses and the old picker grabbed those, showing a useless IP.
     * Primary source: the adapter that owns the default gateway (Windows knows
     * which one is really online). Fallback: the Java enumeration with virtual
     * adapters excluded.
     */
    /**
     * This machine's candidate LAN IPs - the addresses students may type, best
     * first. Primary source: adapters that own the default gateway (Windows
     * knows which one is really online). Then every other site-local address on
     * an adapter students could sit behind: on a shared/hotspot setup the
     * hotspot adapter (e.g. 192.168.137.1) has NO default gateway, and the old
     * gateway-only picker showed the internet-facing address instead - an IP
     * the students could never reach. Virtual-tooling adapters (WSL, Hyper-V,
     * VirtualBox, tunnels) are excluded from the fallback; a Windows Mobile
     * Hotspot adapter is not, despite the "Virtual" in its name.
     */
    private static List<String> lanIps() {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command",
                    "(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } "
                            + "| ForEach-Object { $_.IPv4Address.IPAddress }) -join ' '")
                    .redirectErrorStream(true).start();
            // Wait BEFORE reading: readAllBytes blocks until EOF, so reading first
            // would make this timeout unreachable. Output is one IP line per adapter.
            if (!p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
            } else {
                String outText = new String(p.getInputStream().readAllBytes(),
                        StandardCharsets.UTF_8).trim();
                java.util.regex.Matcher m = java.util.regex.Pattern
                        .compile("\\d{1,3}(\\.\\d{1,3}){3}").matcher(outText);
                while (m.find()) out.add(m.group());
            }
        } catch (Exception ignored) {
        }
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                String name = (ni.getName() + " " + ni.getDisplayName()).toLowerCase();
                if (name.contains("wsl") || name.contains("hyper-v") || name.contains("vethernet")
                        || name.contains("virtualbox") || name.contains("loopback")
                        || name.contains("tunnel") || name.contains("tailscale")
                        || name.contains("tap-")) continue;
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress a = addrs.nextElement();
                    if (!a.isSiteLocalAddress()) continue;
                    out.add(a.getHostAddress());
                }
            }
        } catch (Exception ignored) {
        }
        if (out.isEmpty()) out.add("127.0.0.1");
        return new ArrayList<>(out);
    }

    // ------------------------------------------------------------- beacon --

    /**
     * Broadcast the monitor's presence every two seconds so student PCs can
     * find this machine without typing an IP - the address changes whenever the
     * network changes (hotspot, new room), and a typed IP from yesterday fails
     * silently. The beacon carries the monitor certificate's fingerprint so a
     * student PC can pair automatically; the student connects back to the
     * address the packet actually came from, which is by definition the address
     * it can reach.
     */
    private void startBeacon() {
        stopBeacon();
        Thread t = new Thread(() -> {
            try {
                String fingerprint = CentralTls.monitorCertificateFingerprint();
                byte[] payload = (CentralReporter.BEACON_PREFIX + CENTRAL_TCP_PORT
                        + (fingerprint.isEmpty() ? "" : "@@@" + fingerprint))
                        .getBytes(StandardCharsets.UTF_8);
                while (running) {
                    java.util.LinkedHashSet<String> ips = CentralTls.allLanIpv4s();
                    // Bind one short-lived sender to every active IPv4 interface.
                    // This matters on PCs with Wi-Fi + Ethernet/virtual adapters:
                    // a single unbound socket may route every broadcast through
                    // the wrong interface and students then never discover us.
                    for (String ip : ips) {
                        if (!running) break;
                        int lastDot = ip.lastIndexOf('.');
                        if (lastDot <= 0) continue;
                        try (java.net.DatagramSocket socket = new java.net.DatagramSocket(
                                new InetSocketAddress(InetAddress.getByName(ip), 0))) {
                            socket.setBroadcast(true);
                            byte[] copy = payload.clone();
                            socket.send(new java.net.DatagramPacket(copy, copy.length,
                                    InetAddress.getByName(ip.substring(0, lastDot) + ".255"),
                                    CentralReporter.DISCOVERY_UDP_PORT));
                        } catch (Exception ignored) {
                            // An unavailable adapter must not stop the other interfaces.
                        }
                    }
                    // Also send the limited global broadcast for networks whose
                    // subnet is not /24 and for older access points.
                    try (java.net.DatagramSocket socket = new java.net.DatagramSocket()) {
                        socket.setBroadcast(true);
                        socket.send(new java.net.DatagramPacket(payload, payload.length,
                                InetAddress.getByName("255.255.255.255"),
                                CentralReporter.DISCOVERY_UDP_PORT));
                    } catch (Exception ignored) {}
                    Thread.sleep(2000);
                }
            } catch (Exception ignored) {
                // discovery is best-effort; manual IP entry still works
            }
        }, "CheatGuard-CentralBeacon");
        t.setDaemon(true);
        t.start();
        beaconThread = t;
    }

    private void stopBeacon() {
        Thread t = beaconThread;
        beaconThread = null;
        if (t != null) t.interrupt();
    }

    private static String randomCode() {
        StringBuilder sb = new StringBuilder();
        SecureRandom r = new SecureRandom();
        for (int i = 0; i < 6; i++) sb.append("0123456789".charAt(r.nextInt(10)));
        return sb.toString();
    }

    private static final class ConnectionState {
        private boolean authenticated;
        private boolean helloReceived;
        private final String nonce;
        private String pc = "";
        private String student = "";
        private String course = "";
        private boolean sessionEnded;
        private String recordKey = "";

        private ConnectionState(String nonce) {
            this.nonce = nonce;
        }
    }

    private void markConnectionOffline(String key) {
        if (key == null || key.isBlank()) return;
        synchronized (students) {
            StudentRecord rec = students.get(key);
            if (rec != null) rec.sessionEnded = true;
        }
        SwingUtilities.invokeLater(() -> {
            rebuildStudentTable();
            counters.setText("PCs: " + students.size() + "   Alerts: " + alertCount.get());
        });
    }

    private static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
