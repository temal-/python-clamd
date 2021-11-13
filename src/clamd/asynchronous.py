import asyncio
import struct

from . import scan_response, ResponseError, BufferTooLongError, ConnectionError


class ClamdAsyncNetworkSocket(object):
    """
    Class for using clamd with an async network socket
    """

    def __init__(self, host='127.0.0.1', port=3310, timeout=None):
        """
        class initialisation

        host (string) : hostname or ip address
        port (int) : TCP port
        timeout (float or None) : connect and read timeout
        """

        self.host = host
        self.port = port
        self.timeout = timeout

    async def _init_socket(self):
        """
        internal use only
        """
        connection = asyncio.open_connection(self.host, self.port)

        try:
            return await asyncio.wait_for(connection, self.timeout)
        except asyncio.TimeoutError as e:
            raise ConnectionError("Timeout connecting to {host}:{port}")
        except ConnectionRefusedError as e:
            raise ConnectionError("Error connecting to {host}:{port}. {msg}".format(e.strerror))

    async def ping(self):
        return await self._basic_command("PING")

    async def version(self):
        return await self._basic_command("VERSION")

    async def reload(self):
        return await self._basic_command("RELOAD")

    async def shutdown(self):
        """
        Force Clamd to shutdown and exit

        return: nothing

        May raise:
          - ConnectionError: in case of communication problem
        """
        tx = None
        try:
            rx, tx = await self._init_socket()
            await self._send_command(tx, 'SHUTDOWN')
            # result = self._recv_response()
        finally:
            if tx is not None:
                tx.close()

    async def scan(self, file):
        return await self._file_system_scan('SCAN', file)

    async def contscan(self, file):
        return await self._file_system_scan('CONTSCAN', file)

    async def multiscan(self, file):
        return await self._file_system_scan('MULTISCAN', file)

    async def _basic_command(self, command):
        """
        Send a command to the clamav server, and return the reply.
        """
        tx = None
        try:
            rx, tx = await self._init_socket()
            await self._send_command(tx, command)
            response = (await self._recv_response_multiline(rx)).rsplit("ERROR", 1)
            if len(response) > 1:
                raise ResponseError(response[0])
            else:
                return response[0]
        finally:
            if tx is not None:
                tx.close()

    async def _file_system_scan(self, command, file):
        """
        Scan a file or directory given by filename using multiple threads (faster on SMP machines).
        Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return:
          - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}

        May raise:
          - ConnectionError: in case of communication problem
        """
        tx = None
        try:
            rx, tx = await self._init_socket()
            await self._send_command(tx, command, file)

            dr = {}
            async for result in self._recv_response_multiline(rx).split('\n'):
                if result:
                    filename, reason, status = self._parse_response(result)
                    dr[filename] = (status, reason)

            return dr
        finally:
            if tx is not None:
                tx.close()

    async def instream(self, buff):
        """
        Scan a buffer

        buff  filelikeobj: buffer to scan

        return:
          - (dict): {filename1: ("virusname", "status")}

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem
        """
        tx = None
        try:
            rx, tx = await self._init_socket()
            await self._send_command(tx, 'INSTREAM')

            max_chunk_size = 1024  # MUST be < StreamMaxLength in /etc/clamav/clamd.conf

            chunk = buff.read(max_chunk_size)
            while chunk:
                size = struct.pack(b'!L', len(chunk))
                tx.write(size + chunk)
                await tx.drain()
                chunk = buff.read(max_chunk_size)

            tx.write(struct.pack(b'!L', 0))
            await tx.drain()

            result = await self._recv_response(rx)

            if len(result) > 0:
                if result == 'INSTREAM size limit exceeded. ERROR':
                    raise BufferTooLongError(result)

                filename, reason, status = self._parse_response(result)
                return {filename: (status, reason)}
        finally:
            if tx is not None:
                tx.close()

    async def stats(self):
        """
        Get Clamscan stats

        return: (string) clamscan stats

        May raise:
          - ConnectionError: in case of communication problem
        """
        tx = None
        try:
            rx, tx = await self._init_socket()
            await self._send_command(tx, 'STATS')
            return await self._recv_response_multiline(rx)
        finally:
            if tx is not None:
                tx.close()

    async def _send_command(self, tx, cmd, *args):
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """
        concat_args = ''
        if args:
            concat_args = ' ' + ' '.join(args)

        cmd = 'n{cmd}{args}\n'.format(cmd=cmd, args=concat_args).encode('utf-8')
        tx.write(cmd)
        await tx.drain()

    async def _recv_response(self, rx):
        """
        receive line from clamd
        """
        try:
            line = await asyncio.wait_for(rx.readline(), self.timeout)
            return line.decode('utf-8').strip()
        except asyncio.TimeoutError as e:
            raise ConnectionError("Timeout while reading from socket")

    async def _recv_response_multiline(self, rx):
        """
        receive multiple line response from clamd and strip all whitespace characters
        """
        try:
            content = await asyncio.wait_for(rx.read(), self.timeout)
            return content.decode('utf-8')
        except asyncio.TimeoutError as e:
            raise ConnectionError("Timeout while reading from socket")

    def _parse_response(self, msg):
        """
        parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
        """
        try:
            return scan_response.match(msg).group("path", "virus", "status")
        except AttributeError:
            raise ResponseError(msg.rsplit("ERROR", 1)[0])
