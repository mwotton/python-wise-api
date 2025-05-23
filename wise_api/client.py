from datetime import datetime
from typing import Iterator, Literal

from requests import Response, Session

from .crypto import sign_approval_token
from .exceptions import WiseInvalidPublicKeyError
from .utils import zulu_time

WiseId = int | str


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

    def get_borderless_accounts(self, profile_id: WiseId):
        return self.get("/v1/borderless-accounts", params={"profileId": profile_id})

    def get_balance_statement(
        self,
        profile_id: WiseId,
        balance_id: WiseId,
        *,
        currency: str,
        start: datetime,
        end: datetime,
        type: Literal["pdf", "csv", "json"] = "json",
        compact: bool = False,
    ):
        return self.get(
            f"/v1/profiles/{profile_id}/balance-statements/{balance_id}/statement.{type}",
            params={
                "intervalStart": zulu_time(start),
                "intervalEnd": zulu_time(end),
                "currency": currency,
                "type": "COMPACT" if compact else "FLAT",
            },
        )

    def get_borderless_account_statement(
        self,
        profile_id: WiseId,
        account_id: WiseId,
        *,
        currency: str,
        start: datetime,
        end: datetime,
        type: Literal["pdf", "csv", "json"] = "json",
        compact: bool = False,
    ):
        return self.get(
            f"/v3/profiles/{profile_id}/borderless-accounts/{account_id}/statement.{type}",
            params={
                "intervalStart": zulu_time(start),
                "intervalEnd": zulu_time(end),
                "currency": currency,
                "type": "COMPACT" if compact else "FLAT",
            },
        )

    def get_recipient_accounts(self, profile_id: WiseId):
        return self.get("/v1/accounts", params={"profileId": profile_id})

    def get_recipient_account_by_id(self, account_id: WiseId):
        return self.get(f"/v1/accounts/{account_id}")

    def get_transfer_by_id(self, transfer_id: WiseId):
        return self.get(f"/v1/transfers/{transfer_id}")

    def get_activities(
        self,
        profile_id: WiseId,
        *,
        monetary_resource_type: str | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        size: int | None = None,
    ) -> Iterator[dict]:
        """
        Iterate through activities for a profile, handling pagination automatically.

        Args:
            profile_id: The ID of the profile to fetch activities for.
            monetary_resource_type: Filter activity by resource type.
            status: Filter by activity status.
            since: Filter activity list after a certain timestamp.
            until: Filter activity list until a certain timestamp.
            size: Desired size of the result set per page (min 1, max 100, default 10).

        Yields:
            Dictionaries representing individual activities.
        """
        params = {}
        if monetary_resource_type:
            params["monetaryResourceType"] = monetary_resource_type
        if status:
            params["status"] = status
        if since:
            params["since"] = zulu_time(since)
        if until:
            params["until"] = zulu_time(until)
        if size is not None:
            if not 1 <= size <= 100:
                raise ValueError("Size must be between 1 and 100")
            params["size"] = size

        next_cursor = None
        while True:
            current_params = params.copy()
            if next_cursor:
                current_params["nextCursor"] = next_cursor

            response_data = self.get(f"/v1/profiles/{profile_id}/activities", params=current_params)

            # Assuming the activities are in a list under the key 'activities'
            # Adjust this key if the actual API response structure is different
            activities = response_data.get("activities", [])
            for activity in activities:
                yield activity

            next_cursor = response_data.get("cursor")
            if not next_cursor:
                break
