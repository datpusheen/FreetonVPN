"""Allow bundling tkinter when PyInstaller cannot probe the local Tcl install."""


def pre_find_module_path(hook_api):
    # Keep the normal module search paths. Tcl/Tk files are supplied explicitly
    # by the build command and configured by pyi_rth__tkinter.py.
    return
