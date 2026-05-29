
import re
from .replay_models import ReplayRequest

class AuthorizationMutator:

    @staticmethod
    def swap_bearer_token(request: ReplayRequest, new_token: str):
        headers = dict(request.headers)
        headers["Authorization"] = f"Bearer {new_token}"

        return ReplayRequest(
            method=request.method,
            url=request.url,
            headers=headers,
            body=request.body,
            cookies=request.cookies,
        )

    @staticmethod
    def swap_tenant_id(request: ReplayRequest, old_tenant: str, new_tenant: str):
        body = request.body

        if body:
            body = body.replace(old_tenant, new_tenant)

        url = request.url.replace(old_tenant, new_tenant)

        return ReplayRequest(
            method=request.method,
            url=url,
            headers=request.headers,
            body=body,
            cookies=request.cookies,
        )

    @staticmethod
    def swap_resource_id(request: ReplayRequest, old_id: str, new_id: str):
        body = request.body

        if body:
            body = re.sub(re.escape(old_id), new_id, body)

        url = re.sub(re.escape(old_id), new_id, request.url)

        return ReplayRequest(
            method=request.method,
            url=url,
            headers=request.headers,
            body=body,
            cookies=request.cookies,
        )
