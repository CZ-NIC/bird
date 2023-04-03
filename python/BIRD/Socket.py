import asyncio

class SocketException(Exception):
    def __init__(self, socket, msg):
        Exception.__init__(self, f"Failed to {msg} BIRD Control Socket at {socket.path}")

class ReadException(Exception):
    def __init__(self, socket, line, msg):
        Exception.__init__(self, f"Invalid input on line {line}: {msg}")

class Socket:
    def __init__(self, path):
        self.path = path
        self.reader = None
        self.writer = None

    async def open(self):
        assert(self.reader is None)
        assert(self.writer is None)

        try:
            self.reader, self.writer = await asyncio.open_unix_connection(path=self.path)
        except Exception as e:
            raise SocketException(self, "connect to") from e

        try:
            return await self.read_from_socket()
        except ReadException as e:
            raise SocketException(self, "read hello from") from e

    async def close(self):
        assert(self.reader is not None)
        assert(self.writer is not None)

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception as e:
            raise SocketException(self, "close") from e

        self.reader = None
        self.writer = None

    async def read_from_socket(self):
        current_code = None
        lines = []

        while True:
            line = (await self.reader.readline()).decode()

            if len(line) == 0:
                raise ReadException(self, len(lines)+1, "Connection closed")

            if line[-1] != "\n":
                raise ReadException(self, len(lines)+1, "Received partial data")

            if line[0] == " ":
                if current_code is None:
                    raise ReadException(self, len(lines)+1, "First line can't be unnumbered continuation")
                lines.append({"code": current_code, "data": line[1:-1]})

            elif line[4] == "-" or line[4] == " ":
                try:
                    current_code = int(line[:4])
                except ValueError as e:
                    raise ReadException(self, len(lines)+1, f"Invalid line code: {line[:4]}") from e

                lines.append({"code": current_code, "data": line[5:-1]})

                if line[4] == " ":
                    return lines

    async def command(self, cmd):
        try:
            self.writer.write(f"{cmd}\n".encode())
            await self.writer.drain()
        except Exception as e:
            raise SocketException(self, f"write command {cmd} to") from e

        try:
            return await self.read_from_socket()
        except Exception as e:
            raise SocketException(self, f"read response for command {cmd} from") from e

