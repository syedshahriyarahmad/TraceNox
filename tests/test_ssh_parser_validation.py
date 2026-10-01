from tracenox.analyzer.ssh_parser import parse_ssh_line


def test_parse_failed_login_with_valid_ipv4():
    line = (
        "Sep 12 10:15:22 server sshd[1234]: "
        "Failed password for invalid user admin from 192.0.2.10 port 4422 ssh2"
    )
    event = parse_ssh_line(line)

    assert event is not None
    assert event.event == "authentication_failed"
    assert event.username == "admin"
    assert event.source_ip == "192.0.2.10"


def test_parse_successful_login_with_valid_ipv6():
    line = (
        "Sep 12 10:16:22 server sshd[1234]: "
        "Accepted publickey for analyst from 2001:db8::10 port 4422 ssh2"
    )
    event = parse_ssh_line(line)

    assert event is not None
    assert event.event == "authentication_success"
    assert event.username == "analyst"
    assert event.source_ip == "2001:db8::10"


def test_reject_invalid_ipv4_source():
    line = (
        "Sep 12 10:15:22 server sshd[1234]: "
        "Failed password for admin from 999.999.999.999 port 4422 ssh2"
    )
    assert parse_ssh_line(line) is None


def test_reject_hostname_instead_of_ip():
    line = (
        "Sep 12 10:15:22 server sshd[1234]: "
        "Failed password for admin from attacker.example port 4422 ssh2"
    )
    assert parse_ssh_line(line) is None


def test_reject_empty_and_unrelated_lines():
    assert parse_ssh_line("") is None
    assert parse_ssh_line("ordinary system message") is None
    assert parse_ssh_line("   ") is None
