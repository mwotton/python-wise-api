from datetime import datetime

from requests import Response, Session

from .crypto import sign_approval_token
from .exceptions import WiseInvalidPublicKeyError
from .utils import zulu_time


def sca_required(resp: Response) -> bool:
    return (
        resp.status_code == 403
        and resp.headers.get("x-2fa-approval-result") == "REJECTED"
    )


class APIClient:
    session_class = Session
    sandbox_url = "https://api.sandbox.transferwise.tech"
    production_url = "https://api.transferwise.com"

    def __init__(self, api_key: str, signing_key: str, production: bool = True):
        self.api_key = api_key
        self.signing_key = signing_key
        self.production = production
        self.session = self.session_class()

    @property
    def base_url(self):
        if not self.production:
            return self.sandbox_url

        return self.production_url

    def get(self, path: str, params=None):
        url = self.base_url + path
        headers = {"authorization": f"Bearer {self.api_key}"}

        if params is None:
            params = {}

        resp = self.session.get(url, headers=headers, params=params)

        if sca_required(resp):
            token = resp.headers["x-2fa-approval"]
            signature = sign_approval_token(self.signing_key, token)

            headers["x-2fa-approval"] = token
            headers["x-signature"] = signature
            resp = self.session.get(url, headers=headers, params=params)

            if resp.status_code == 400:
                raise WiseInvalidPublicKeyError(
                    "Strong Customer Authentication has been rejected."
                )

        resp.raise_for_status()

        return resp.json()

    def get_current_user(self):
        return self.get("/v1/me")

    def get_user_profiles(self):
        return self.get("/v1/profiles")

    def get_addresses(self):
        return self.get("/v1/addresses")

    def get_borderless_accounts(self, profile_id: int | str):
        return self.get("/v1/borderless-accounts", params={"profileId": profile_id})

    def get_borderless_account_statement(
        self,
        profile: int,
        account_id: int,
        currency: str,
        start: datetime,
        end: datetime,
    ):

        return self.get(
            f"/v3/profiles/{profile}/borderless-accounts/{account_id}/statement.json",
            params={
                "intervalStart": zulu_time(start),
                "intervalEnd": zulu_time(end),
                "currency": currency,
            },
        )

    def get_recipient_accounts(self, profile_id: int | str):
        return self.get("/v1/accounts", params={"profileId": profile_id})

    def get_recipient_account_by_id(self, account_id: int | str):
        return self.get(f"/v1/accounts/{account_id}")

    def get_transfer_by_id(self, transfer_id: int | str):
        return self.get(f"/v1/transfers/{transfer_id}")
