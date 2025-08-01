from cape_parsers.CAPE.community.AgentTesla import extract_config


def test_agenttesla():
    # AgentTeslaV5
    with open("tests/data/malware/893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {'Protocol': 'SMTP', 'CNCs': ['mail.guestequipment.com.au'], 'Username': 'sendlog@guestequipment.com.au', 'Password': 'Clone89!', 'EmailTo': 'info@marethon.com', 'Persistence_Filename': 'newfile.exe', 'ExternalIPCheckServices': ['http://ip-api.com/line/?fields=hosting']}
