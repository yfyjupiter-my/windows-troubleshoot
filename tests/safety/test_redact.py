from app_triage.safety.redact import redact


def test_redact_user_paths():
    assert redact(r"C:\Users\Tester\AppData", "tester") == r"C:\Users\%USER%\AppData"
    assert redact("C:/Users/tester/x", "tester") == r"C:\Users\%USER%/x"
    assert redact(r"c:\users\TESTER", "Tester") == r"c:\Users\%USER%"
    # a different user is untouched, including one sharing the prefix
    assert redact(r"C:\Users\other\x", "tester") == r"C:\Users\other\x"
    assert redact(r"C:\Users\tester2\x", "tester") == r"C:\Users\tester2\x"


def test_redact_multiple_and_in_context():
    text = r'"C:\Users\tester\a.exe" --dir=D:\Users\tester, C:\Users\tester'
    assert redact(text, "tester") == (
        r'"C:\Users\%USER%\a.exe" --dir=D:\Users\%USER%, C:\Users\%USER%'
    )


def test_redact_special_chars_and_unicode_username():
    assert redact(r"C:\Users\a.b\x", "a.b") == r"C:\Users\%USER%\x"
    assert redact(r"C:\Users\axb\x", "a.b") == r"C:\Users\axb\x"
    assert redact(r"C:\Users\张三\桌面", "张三") == r"C:\Users\%USER%\桌面"


def test_redact_empty_username_is_noop():
    assert redact(r"C:\Users\tester\x", "") == r"C:\Users\tester\x"
