import pytest

from app_triage.rules import match_vendor


@pytest.mark.parametrize("text,vendor", [
    (r"C:\Users\a\AppData\Local\Kingsoft\WPS Office\ksolaunch.exe", "WPS (金山办公)"),
    ("WPS.PIC.jpg", "WPS (金山办公)"),
    ("wpscloudsvr", "WPS (金山办公)"),
    ("KWPS.Document.12", "WPS (金山办公)"),
    ("KET.Sheet.12", "WPS (金山办公)"),
    ("KWPP.Presentation.12", "WPS (金山办公)"),
    (r"C:\Program Files (x86)\2345Soft\2345Pic\2345PicViewer.exe", "2345"),
    (r"C:\Program Files\Ludashi\ComputerZTray.exe", "鲁大师"),
    (r"C:\Program Files\360\360safe\safemon\360tray.exe", "360"),
])
def test_match_vendor_known(text, vendor):
    assert match_vendor(text).name == vendor


def test_match_vendor_no_false_positive():
    assert match_vendor(r"C:\Windows\System32\wpshelper.dll", "Microsoft.Photos") is None
