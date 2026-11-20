import sys


def test_active_gui_is_pyside6_and_not_tkinter():
    from passguard import gui
    assert gui is not None
    assert "tkinter" not in sys.modules
    assert hasattr(gui, "PassGuardWindow")
    assert hasattr(gui, "launch_gui")
