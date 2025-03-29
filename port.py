class Port:

    def __init__(self, host, port, status, is_open=False):
        self.__host = host
        self.__port = port
        self.__status = status
        self.__is_open = is_open

    def check(self):
        return self.__is_open

    def get_port(self):
        return self.__port

    def get_host(self):
        return self.__host

    def get_status(self):
        return self.__status
    
    def __str__(self):
        return f"{self.__host}:{self.__port} status: {self.__status} "