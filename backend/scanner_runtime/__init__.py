"""Runtime selection and execution for real security scanner integrations."""

__all__ = ["ScannerManager", "ToolRegistry", "build_default_registry"]


def __getattr__(name: str):
    # Keep package import side-effect free: BaseScanner imports executors from this
    # package before the registry imports scanner implementations.
    if name == "ScannerManager":
        from backend.scanner_runtime.scanner_manager import ScannerManager
        return ScannerManager
    if name in {"ToolRegistry", "build_default_registry"}:
        from backend.scanner_runtime.tool_registry import ToolRegistry, build_default_registry
        return {"ToolRegistry": ToolRegistry, "build_default_registry": build_default_registry}[name]
    raise AttributeError(name)
