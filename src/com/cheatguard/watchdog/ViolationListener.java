package com.cheatguard.watchdog;

// OWNER: Rohan — violation event routing to policy and central monitoring.

import com.cheatguard.core.Violation;

/**
 * OOP Concept: INTERFACE (abstraction)
 * --------------------------------------
 * WatchdogEngine never needs to know the AlarmPlayer/ScreenLocker classes directly.
 * It only knows that "when a violation happens, an onViolation() call is made".
 * Main.java hands WatchdogEngine an implementation (lambda) at run-time that decides
 * exactly what to do (sound the alarm, lock the screen, etc).
 * This is "loose coupling" - separate modules are not tightly bound to each other.
 */
public interface ViolationListener {
    void onViolation(Violation violation);
}
