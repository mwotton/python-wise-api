class WiseAPIError(Exception):
    pass


class WiseInvalidPublicKeyError(WiseAPIError):
    """
    Raised when SCA has been sent and subsequently rejected by Wise.

    Most likely, the public key has not been set up correctly in Wise.

    Information on Strong Customer Authentication:
    https://api-docs.transferwise.com/#strong-customer-authentication
    """
