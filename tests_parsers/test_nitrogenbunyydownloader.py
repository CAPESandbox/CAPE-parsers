from cape_parsers.CAPE.core.NitroBunnyDownloader import extract_config


def test_nitrogenbunnydownloader():
    with (open("tests/data/malware/960e59200ec0a4b5fb3b44e6da763f5fec4092997975140797d4eec491de411b", "rb") as data):
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "https://617e7511-4.b-cdn.net/s?k=electronics",
                "https://617e7511-4.b-cdn.net/gp/product/B08J5W8Q7N",
                "https://617e7511-4.b-cdn.net/cart",
                "https://617e7511-4.b-cdn.net/hz/wishlist/ls/26564",
                "https://38.132.122.237/s?k=electronics",
                "https://38.132.122.237/gp/product/B08J5W8Q7N",
                "https://38.132.122.237/cart",
                "https://38.132.122.237/hz/wishlist/ls/26564"],
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "raw": {
                "http_header_items": [
                    "Accept: application/json, application/javascript, text/javascript; charset=utf-8",
                    "Content-Type: application/json; charset=utf-8",
                    "X-Amazon-Trace-Id: Base64Encode(intern-session_01234567890)",
                    "X-Amz-User-Agent: AmazonEnterpriseApplication/android-1.0.1 (Android 9API HoneyComb)",
                    "X-Amz-Target: AmazonEnterpriseClient.BusinessLogic",
                    "X-Amz-Date: 2038-03-14T03:14:07Z",
                    "Amz-Safe-Signature: TURBECOMPLEXification_0123456789",
                    "Amz-Security-Flag: Amazon8Imag genitalsHTLM5",
                    "Cookie: sessionId=321116abbcdefXXxc8qRVfk; expires=600"],
                "unknown_1": 2261840800,
                "unknown_2": 1765860472,
                "blob_size": 1548,
            }
        }
