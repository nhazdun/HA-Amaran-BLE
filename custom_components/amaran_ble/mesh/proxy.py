"""GATT bearer for the mesh provisioning and proxy services.

Wraps a connected ``BleakClient`` and handles proxy SAR framing in both
directions. The caller owns the connection so Home Assistant's
``bleak_retry_connector`` can manage establishment and retries.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from .pdu import ProxyReassembler, proxy_segment

_LOGGER = logging.getLogger(__name__)

# Mesh Provisioning Service (Mesh Profile 7.1).
SERVICE_PROVISIONING = "00001827-0000-1000-8000-00805f9b34fb"
CHAR_PROVISIONING_DATA_IN = "00002adb-0000-1000-8000-00805f9b34fb"
CHAR_PROVISIONING_DATA_OUT = "00002adc-0000-1000-8000-00805f9b34fb"

# Mesh Proxy Service (Mesh Profile 7.2).
SERVICE_PROXY = "00001828-0000-1000-8000-00805f9b34fb"
CHAR_PROXY_DATA_IN = "00002add-0000-1000-8000-00805f9b34fb"
CHAR_PROXY_DATA_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

#: Conservative proxy PDU size when the negotiated ATT MTU is unknown.
DEFAULT_MTU = 20

PduHandler = Callable[[int, bytes], Coroutine[Any, Any, None] | None]


class MeshGattBearer:
    """Sends and receives proxy PDUs over one GATT service."""

    def __init__(
        self,
        client: BleakClient,
        data_in: str,
        data_out: str,
        on_pdu: PduHandler,
    ) -> None:
        """Bind to a connected client and the in/out characteristics to use."""
        self._client = client
        self._data_in = data_in
        self._data_out = data_out
        self._on_pdu = on_pdu
        self._reassembler = ProxyReassembler()
        self._write_lock = asyncio.Lock()

    @classmethod
    def provisioning(cls, client: BleakClient, on_pdu: PduHandler) -> MeshGattBearer:
        """Bearer bound to the Mesh Provisioning Service."""
        return cls(
            client, CHAR_PROVISIONING_DATA_IN, CHAR_PROVISIONING_DATA_OUT, on_pdu
        )

    @classmethod
    def proxy(cls, client: BleakClient, on_pdu: PduHandler) -> MeshGattBearer:
        """Bearer bound to the Mesh Proxy Service."""
        return cls(client, CHAR_PROXY_DATA_IN, CHAR_PROXY_DATA_OUT, on_pdu)

    @property
    def mtu(self) -> int:
        """Usable proxy PDU size, i.e. the ATT MTU minus the 3-byte ATT header."""
        try:
            mtu = int(self._client.mtu_size) - 3
        except Exception:  # noqa: BLE001 - backends raise various types pre-discovery
            return DEFAULT_MTU
        return max(DEFAULT_MTU, mtu)

    async def start(self) -> None:
        """Subscribe to the data-out characteristic."""
        await self._client.start_notify(self._data_out, self._handle_notify)

    async def stop(self) -> None:
        """Unsubscribe, ignoring errors from an already-dropped link."""
        try:
            await self._client.stop_notify(self._data_out)
        except Exception as err:  # noqa: BLE001 - teardown is best effort
            _LOGGER.debug("stop_notify failed: %s", err)

    async def send(self, msg_type: int, payload: bytes) -> None:
        """Frame and write a payload, segmenting it if it exceeds the MTU."""
        pdus = proxy_segment(msg_type, payload, self.mtu)
        _LOGGER.debug(
            "GATT TX %s type=%d mtu=%d %s",
            self._data_in[4:8],
            msg_type,
            self.mtu,
            " ".join(p.hex() for p in pdus),
        )
        async with self._write_lock:
            for pdu in pdus:
                await self._client.write_gatt_char(self._data_in, pdu, response=False)

    def _handle_notify(
        self, _characteristic: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        """Feed a notification into the reassembler and dispatch when complete."""
        _LOGGER.debug("GATT RX %s %s", self._data_out[4:8], bytes(data).hex())
        result = self._reassembler.push(bytes(data))
        if result is None:
            return

        msg_type, payload = result
        outcome = self._on_pdu(msg_type, payload)
        if asyncio.iscoroutine(outcome):
            # Bleak invokes this callback from the event loop, so scheduling is safe.
            task = asyncio.create_task(outcome)
            task.add_done_callback(_log_task_error)


def _log_task_error(task: asyncio.Task[Any]) -> None:
    """Surface exceptions from fire-and-forget PDU handlers."""
    if task.cancelled():
        return
    if (err := task.exception()) is not None:
        _LOGGER.error("mesh PDU handler failed: %s", err)
