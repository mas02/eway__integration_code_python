import string
import random
import base64  # import base64 encode and decode
import json  # import json


class Common(object):
    def get_random_code(self, stringLen, randomType=None):
        """
        func returns the random string based on type and length
        """
        if randomType == "alphabetic":
            letters = string.ascii_letters
            key = ''.join(random.choice(letters) for i in range(stringLen))
        elif randomType == "numeric":
            letters = string.digits
            key = ''.join(random.choice(letters) for i in range(stringLen))
        else:
            letters = string.ascii_letters + string.digits
            key = ''.join(random.choice(letters) for i in range(stringLen))

        return key


