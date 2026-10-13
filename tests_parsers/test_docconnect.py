from cape_parsers.CAPE.core.DocConnect import extract_config


def test_docconnect_162c0d3e671ddf4f7f3ae5681da5272111eab6588bc53843cc604fc386634594():
    with open("tests/data/malware/162c0d3e671ddf4f7f3ae5681da5272111eab6588bc53843cc604fc386634594", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "https://networkservice.cyou/api",
                "https://networkservice.cyou/hubs/screen",
            ],
            "raw": {
                "OrganizationId": "175bdd28-5c79-4483-9b0c-91dc77621505",
                "Email": "73656C6D617761727269636B40676D61696C2E636F6D",
                "InstallToken": "",
                "Email_ascii": "selmawarrick@gmail.com",
            },
        }
