
import asyncio

import config as config
from models.port import Port
from log import logger

from base import Scan

class TCPConnect(Scan):

    async def _connect_one(self, port: int) -> str:

        logger_message = f"Attempting to connect to {self._host} on port {port}..."
        logger.info(logger_message)

        if self._verbosity >= config.MEDIUM_VERBOSITY:
            print(logger_message)

        try:
            conn = asyncio.open_connection(self._host, port)
            _, writer = await asyncio.wait_for(conn, timeout=self._timeout)
            writer.close()

            # Ensure the writer is closed
            try:
                await writer.wait_closed()
            except Exception as e:
                logger.error(f"Error while closing writer: {e}")
                pass
            return config.OPEN_PORT
        except (ConnectionRefusedError, OSError) as e:
            if isinstance(e, ConnectionRefusedError):
                logger.warning(
                    f"Connection refused on {self._host}:{port} - port is CLOSED"
                )
                return config.CLOSED_PORT
            if getattr(e, "errno", None) in config.ERRORNO_LIST:
                logger.warning(
                    f"Connection failed on {self._host}:{port} due to network error {e.errno}"
                )
                return config.FILTERED_PORT
            logger.error(
                f"Connection to {self._host}:{port} failed due to packet drop or firewall"
            )
            return config.FILTERED_PORT
        except asyncio.TimeoutError:
            logger.warning(f"Connection to {self._host}:{port} failed due to timeout")
            return config.FILTERED_PORT

    async def _scan_batch_connect(
        self, port_list: list[Port], concur: int = config.DEFAULT_CONCURRENCY_FOR_SCANS
    ) -> None:
        host = self._host
        sem = asyncio.Semaphore(concur)

        logger_message = (
            f"Starting TCP Connect scan on host {self._host} for ports in {self._ports[0]} to {self._ports[-1]}."
        )

        logger.info(logger_message)
        if self._ports[-1] > config.THRESHOLD_FOR_SLOW_SCAN:
            logger_message = (
                f"Scanning more than {config.THRESHOLD_FOR_SLOW_SCAN} ports may be slow."
            )
            logger.warning(logger_message)
            print(logger_message)

        if self._verbosity >= config.MINIMUM_VERBOSITY:
            print(logger_message)

        async def scan_port(port: int):
            # Retry loop, avoiding recursion
            status = config.FILTERED_PORT

            for attempt in range(self._retry + 1):
                logger_message = (
                    f"Scanning port {port} on host {host}, attempt {attempt + 1}..."
                )
                logger.info(logger_message)

                if self._verbosity >= config.MEDIUM_VERBOSITY:
                    print(logger_message)

                if attempt > 0:
                    logger_message = (
                        f"Retrying port {port} on host {host}, attempt {attempt + 1}..."
                    )
                    logger.warning(logger_message)
                    if self._verbosity == config.MAX_VERBOSITY:
                        print(logger_message)

                async with sem:
                    logger.info(
                        f"Waiting for connection slot for port {port} on host {host}..."
                    )
                    status = await self._connect_one(port)
                if status == config.OPEN_PORT:
                    break

            tested = Port(host, port, status, status == config.OPEN_PORT)

            if self._verbosity == config.MAX_VERBOSITY:
                self.verbosity_print(port_obj=tested)

            return tested

        tasks = [asyncio.create_task(scan_port(p)) for p in self._ports]

        logger.info(f"Waiting for scan tasks to complete for host {host}...")

        # Gather results as they complete
        for t in asyncio.as_completed(tasks):
            port_list.append(await t)

    async def scan_host(
        self,
        port_list,
    ) -> None:

        await self._scan_batch_connect(port_list)

        if self._banner:
            await self._get_banners(port_list)