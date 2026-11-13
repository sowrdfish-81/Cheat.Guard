# Cheat.Guard data flow

```text
Setup UI (Rafa)
  -> AppConfig / allowlist policy (Rohan)
  -> ExamSession + WatchdogEngine (Muhit)
  -> Process/file/device/DNS checks
  -> Violation + LogManager
  -> CentralReporter (Rohan)
  -> CentralMonitorPanel (Rafa)
  -> ranking/highlighting and invigilator decision
```

Session shutdown reverses the flow: Muhit's enforcement layer restores the
machine, the session log is sealed/backed up, and Rafa's UI reports completion.
Rohan's network layer supplies pairing, TLS and event delivery throughout.
