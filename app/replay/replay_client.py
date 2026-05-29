
import time
import httpx
from .replay_models import ReplayRequest, ReplayResult

class ReplayClient:
    def __init__(self, timeout: int = 30, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def replay(self, request: ReplayRequest) -> ReplayResult:
        start = time.time()

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True,
        ) as client:

            response = await client.request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                content=request.body,
                cookies=request.cookies,
            )

        duration_ms = int((time.time() - start) * 1000)

        return ReplayResult(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
            duration_ms=duration_ms,
        )
