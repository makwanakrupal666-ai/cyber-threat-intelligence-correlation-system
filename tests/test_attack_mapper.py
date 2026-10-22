from backend.attack.attack_mapper import (
    build_technique_index,
    find_rule_matches,
    get_attack_technique,
    map_behavior_to_attack
)


def sample_attack_data():
    return {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern-power",
                "name": "PowerShell",
                "description": "PowerShell execution.",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001"
                    }
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern-wmi",
                "name": "Windows Management Instrumentation",
                "description": "WMI execution.",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1047"
                    }
                ]
            }
        ]
    }


def test_build_technique_index():

    data = sample_attack_data()

    index = build_technique_index(
        data
    )

    assert "T1059.001" in index
    assert "T1047" in index


def test_find_rule_matches():

    text = (
        "The attacker executed "
        "PowerShell commands."
    )

    matches = find_rule_matches(
        text
    )

    technique_ids = [
        item["technique_id"]
        for item in matches
    ]

    assert "T1059.001" in technique_ids


def test_map_behavior_to_attack():

    data = sample_attack_data()

    text = (
        "The malware executed "
        "PowerShell commands."
    )

    results = map_behavior_to_attack(
        text,
        attack_data=data
    )

    assert len(results) == 1

    assert results[0][
        "technique_id"
    ] == "T1059.001"

    assert results[0][
        "technique_name"
    ] == "PowerShell"

    assert (
        "execution"
        in results[0]["tactics"]
    )


def test_wmi_mapping():

    data = sample_attack_data()

    text = (
        "The attacker used WMI "
        "to execute commands."
    )

    results = map_behavior_to_attack(
        text,
        attack_data=data
    )

    assert len(results) == 1

    assert results[0][
        "technique_id"
    ] == "T1047"


def test_no_behavior_match():

    data = sample_attack_data()

    text = (
        "The report contained "
        "an IP address."
    )

    results = map_behavior_to_attack(
        text,
        attack_data=data
    )

    assert results == []


def test_get_attack_technique():

    data = sample_attack_data()

    result = get_attack_technique(
        "T1059.001",
        attack_data=data
    )

    assert result is not None
    assert result[
        "technique_id"
    ] == "T1059.001"
    assert result[
        "name"
    ] == "PowerShell"