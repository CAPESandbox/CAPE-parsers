from cape_parsers.CAPE.core.AdaptixBeacon import extract_config


def test_adaptixbeacon():
    # Adaptix Beacon
    with open("tests/data/malware/f78f5803be5704420cbb2e0ac3c57fcb3d9cdf443fbf1233c069760bee115b5d", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "raw": {
                "cryptokey": "9030edf2700574ff942f8dadb826fac8",
                "cryptokey_type": "RC4",
                "agent_type": "BE4C0149",
                "use_ssl": 1,
                "servers": ["689535ed-3.b-cdn.net"],
                "ports": [443],
                "http_method": "POST",
                "uri": "/amazon/Trust/disputes/press-requests.php",
                "parameter": "A-Wabbon-Id",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/131.0.2903.86",
                "http_headers": "Accept: application/json, application/javascript, text/javascript; charset=utf-8\r\nContent-Type: application/json; charset=utf-8\r\nX-Amazon-Trace-Id: Base64Encode(intern-session_01234567890)\r\nX-Amz-User-Agent: AmazonEnterpriseApplication/android-1.0.1 (Android 9API HoneyComb)\r\nX-Amz-Target: AmazonEnterpriseClient.BusinessLogic\r\nX-Amz-Date: 2038-03-14T03:14:07Z\r\nAmz-Safe-Signature: TURBECOMPLEXification_0123456789\r\nAmz-Security-Flag: Amazon8Imag genitalsHTLM5\r\nCookie: sessionId=321116abbcdefXXxc8qRVfk; expires=600\r\n",
                "ans_pre_size": 26,
                "ans_size": 21,
                "kill_date": 0,
                "working_time": 0,
                "sleep_delay": 20,
                "jitter_delay": 20,
            },
            "cryptokey": "9030edf2700574ff942f8dadb826fac8",
            "cryptokey_type": "RC4",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/131.0.2903.86",
            "CNCs": ["https://689535ed-3.b-cdn.net:443/amazon/Trust/disputes/press-requests.php"],
        }
