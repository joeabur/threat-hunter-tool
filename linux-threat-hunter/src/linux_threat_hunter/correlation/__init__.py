"""Correlation is implemented as declarative ``type: correlation`` rules.

See ``rules_engine.engine.Engine._correlate``: findings from two rule sets are linked only
when they share an identifier (pid, path, ip, ...) and, when both have event timestamps and
a window is configured, occur within that window.
"""
