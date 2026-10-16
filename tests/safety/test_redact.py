import json

from app_triage.safety.redact import redact


def test_redact_user_paths():
    assert redact(r"C:\Users\Tester\AppData", "tester") == r"C:\Users\%USER%\AppData"
    assert redact("C:/Users/tester/x", "tester") == "C:/Users/%USER%/x"
    assert redact(r"c:\users\TESTER", "Tester") == r"c:\users\%USER%"
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


def test_redact_keeps_json_encoded_paths_valid():
    encoded = json.dumps({"p": r"C:\Users\tester\x"})
    assert json.loads(redact(encoded, "tester")) == {"p": r"C:\Users\%USER%\x"}
    assert redact(r"C:\\Users\\tester\\x", "tester") == r"C:\\Users\\%USER%\\x"


def test_redact_computer_suffixed_profile_names():
    assert redact(r"C:\Users\tester.DESKTOP-ABC\x", "tester") == r"C:\Users\%USER%.DESKTOP-ABC\x"
    assert redact(r"C:\Users\tester-PC\x", "tester") == r"C:\Users\%USER%-PC\x"
    assert redact(r"C:\Users\tester_2\x", "tester") == r"C:\Users\tester_2\x"


# ---- R18: every form of the user name, wherever it follows a slash ---------------------------

def test_redact_name_after_any_separator():
    from app_triage.safety.redact import redact
    assert redact(r"DESKTOP-1\tester", "tester") == r"DESKTOP-1\%USER%"
    assert redact("//server/tester/share", "tester") == "//server/%USER%/share"
    assert redact(r"DESKTOP-1\tester2 tester", "tester") == r"DESKTOP-1\tester2 tester"


def test_redact_several_names_longest_first():
    assert redact(r"C:\Users\tom.PC\x DESKTOP\TKGOH", "tkgoh", "tom.pc", "") == \
        r"C:\Users\%USER%\x DESKTOP\%USER%"


def test_redactor_names_from_system_and_data_stays_valid_json():
    from app_triage.safety.redact import Redactor
    from app_triage.sysapi.fake import FakeSystem

    class RenamedAccount(FakeSystem):  # Microsoft account: USERNAME differs from the profile folder
        def username(self):
            return "Tom"

        def known_folders(self):
            return {**super().known_folders(), "UserProfile": "C:\\Users\\tkgoh\\"}

    r = Redactor.for_system(RenamedAccount())
    assert sorted(n.lower() for n in r.names) == ["tkgoh", "tom"]
    data = {"author": r"DESKTOP-1\TOM", "p": [r"C:\Users\tkgoh\a", "\nancy"], r"C:\Users\tkgoh": 1}
    assert r.data(data) == {"author": r"DESKTOP-1\%USER%", "p": [r"C:\Users\%USER%\a", "\nancy"],
                            r"C:\Users\%USER%": 1}
    assert Redactor.for_system(FakeSystem()).names == ("tester",)  # deduplicated
