"""DreadGOAD benchmark runner.

Drives any LangGraph-registered agent through an Active Directory attack
range built by the upstream `DreadGOAD <https://github.com/dreadnode/DreadGOAD>`_
Go CLI, captures per-run evidence (LangSmith trace, OPPLAN, findings,
workspace tarball, cost breakdown), and writes a per-agent grid summary.

See ``benchmark/dreadgoad/README.md`` for the operator guide.
"""
