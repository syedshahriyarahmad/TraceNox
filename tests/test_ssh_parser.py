from tracenox.analyzer.ssh_parser import parse_ssh_line


def test_failed_ssh_login():
    line = (
        "Sep 21 03:20:10 kali sshd[1234]: "
        "Failed password for testuser from 192.168.1.50 "
        "port 22 ssh2"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event == "authentication_failed"
    assert event.username == "testuser"
    assert event.source_ip == "192.168.1.50"


def test_successful_ssh_login():
    line = (
        "Sep 21 03:21:02 kali sshd[1239]: "
        "Accepted password for testuser from 192.168.1.50 "
        "port 22 ssh2"
    )

    event = parse_ssh_line(line)

    assert event is not None
    assert event.event == "authentication_success"
    assert event.username == "testuser"
    assert event.source_ip == "192.168.1.50"


def test_unrelated_log_line():
    line = (
        "Sep 21 03:22:00 kali systemd[1]: "
        "Started some service."
    )

    event = parse_ssh_line(line)

    assert event is None

