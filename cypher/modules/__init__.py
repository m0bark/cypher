"""Built-in and adapter OSINT modules.

Each submodule defines one or more BaseModule subclasses. The registry imports
every submodule here to discover them; keep optional third-party imports inside
run() so discovery never fails on a missing dependency.
"""
