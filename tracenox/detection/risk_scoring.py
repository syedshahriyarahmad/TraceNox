from collections import Counter

from tracenox.models.event import SecurityEvent


def calculate_risk_score(
    events: list[SecurityEvent],
    findings: list[dict],
) -> dict:
    """Calculate a transparent risk score from investigation evidence."""

    score = 0
    reasons = []

    failed_events = [
        event
        for event in events
        if event.event == "authentication_failed"
    ]

    successful_events = [
        event
        for event in events
        if event.event == "authentication_success"
    ]

    failed_count = len(failed_events)

    usernames = {
        event.username
        for event in failed_events
        if event.username
    }

    # Evidence 1: repeated authentication failures
    if failed_count >= 3:
        points = min(failed_count * 5, 30)
        score += points
        reasons.append(
            f"{failed_count} failed authentication attempts (+{points})"
        )

    # Evidence 2: successful login after failed attempts
    failed_then_success = [
        finding
        for finding in findings
        if finding["detection"] == "ssh_failed_then_success"
    ]

    if failed_then_success:
        score += 35
        reasons.append(
            "Successful login detected after repeated failures (+35)"
        )

    # Evidence 3: multiple usernames targeted
    if len(usernames) >= 3:
        score += 15
        reasons.append(
            f"{len(usernames)} usernames targeted (+15)"
        )
    elif len(usernames) == 2:
        score += 10
        reasons.append(
            "2 usernames targeted (+10)"
        )

    # Evidence 4: successful authentication exists
    if successful_events:
        score += 10
        reasons.append(
            f"{len(successful_events)} successful authentication event(s) (+10)"
        )

    # Evidence 5: multiple detection signals
    if len(findings) >= 2:
        score += 10
        reasons.append(
            f"{len(findings)} detection signals (+10)"
        )

    score = min(score, 100)

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }
