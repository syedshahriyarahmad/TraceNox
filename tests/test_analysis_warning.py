from tracenox.analyzer.pipeline import analyze_log_file


def test_empty_log_has_analysis_warning(tmp_path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("")

    result = analyze_log_file(str(log_file))

    assert result["parsed_events"] == 0
    assert result["analysis_warning"]
    assert "no security conclusion" in result["analysis_warning"].lower()


def test_unrecognized_log_has_analysis_warning(tmp_path):
    log_file = tmp_path / "unrelated.log"
    log_file.write_text("This is not an SSH authentication log line.\\n")

    result = analyze_log_file(str(log_file))

    assert result["parsed_events"] == 0
    assert result["analysis_warning"]
    assert "malformed" in result["analysis_warning"].lower()


def test_recognized_ssh_events_have_no_analysis_warning(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Sep 11 10:15:30 server sshd[1234]: "
        "Failed password for admin from 192.0.2.10 port 2222 ssh2\\n"
    )

    result = analyze_log_file(str(log_file))

    assert result["parsed_events"] == 1
    assert result["analysis_warning"] is None
