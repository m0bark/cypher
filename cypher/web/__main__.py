"""Allow `python -m cypher.web` to launch the UI."""

from .server import serve

if __name__ == "__main__":
    serve()
