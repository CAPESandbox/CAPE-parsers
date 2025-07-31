# https://youtu.be/C_ijc7A5oAc?list=OLAK5uy_kGTSX7lmPmKwIVzgFLqd0x3dSF6HQhE-I
from contextlib import suppress

HAVE_MLW_CONFIGS = False
with suppress(ImportError):
    # We do not install this by default as is outdated now, but if installed will be imported
    from malwareconfig.common import Decoder

    HAVE_MLW_CONFIGS = True


# ToDo add xfail if not HAVE_MLW_CONFIGS
class TEST_RATS(Decoder):
    decoder_name = "TestRats"
    decoder__version = 1
    decoder_author = "doomedraven"
    decoder_description = "Test module to ensure that framework loads properly."

    def __init__(self):
        pass
