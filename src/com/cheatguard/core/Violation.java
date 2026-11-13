package com.cheatguard.core;

// ============================================================================
// SHARED FILE OWNERSHIP
// Muhit  : security violation types and enforcement severity.
// Rohan  : event creation, transport fields and central-monitor aggregation.
// Rafa   : labels, display text and UI presentation mapping.
// ============================================================================

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * OOP Concept: ENCAPSULATION
 * ---------------------------
 * This class represents a single "violation" (cheating attempt).
 * All fields are 'private' -> no outside class can change a field directly;
 * it can only be read through getters. This is important for data safety,
 * so the log is never accidentally tampered with by any other class.
 */
public class Violation {

    /**
     * INFO: tidy-up events that are not misconduct. NOTICE: the student tried
     * something that was blocked (a denied website lookup) — shown in yellow,
     * because the enforcement worked and nothing got through. WARNING/CRITICAL:
     * genuine red flags that count on the alert counter.
     */
    public enum Severity { INFO, NOTICE, WARNING, CRITICAL }

    private final LocalDateTime timestamp;
    private final String type;        // e.g. "ILLEGAL_PROCESS", "USB_INSERTED", "PROHIBITED_SITE"
    private final String description; // human readable detail
    private final Severity severity;

    public Violation(String type, String description, Severity severity) {
        this.timestamp = LocalDateTime.now();
        this.type = type;
        this.description = description;
        this.severity = severity;
    }

    public LocalDateTime getTimestamp() { return timestamp; }
    public String getType() { return type; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }

    /** Converts severity into the central monitor ranking/highlight signal. */
    public boolean isRedFlag() {
        return severity == Severity.CRITICAL || severity == Severity.WARNING;
    }

    /**
     * Single-line format for writing to the log.
     * CRITICAL/WARNING violations are marked with a [RED-FLAG] tag,
     * so the GUI dashboard can highlight them in red.
     *
     * Line breaks in the description are flattened first: descriptions can carry
     * data from outside (process names, hosts) and a raw newline would let a crafted
     * name forge extra log lines that the dashboard would parse as real events.
     */
    @Override
    public String toString() {
        String tag = severity == Severity.NOTICE ? "[NOTICE]"
                : isRedFlag() ? "[RED-FLAG]" : "[NORMAL]";
        String ts = timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String safeDescription = description == null ? "" : description.replaceAll("[\\r\\n\\t]+", " ");
        String safeType = type == null ? "EVENT" : type.replaceAll("[\\r\\n\\t]+", " ");
        return String.format("%s %s %s :: %s - %s", ts, tag, severity, safeType, safeDescription);
    }
}
