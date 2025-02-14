
"""
This file contains the implementation of the network events in
MEOW. Specifically, it contains the functions for creating a socket
event and validating said events, the socket event pattern class, and
the socket event monitor class. This implementation was tested in the
test suite in test_socket.py.

Author(s): Nikolaj Sørensen
"""

import glob
import threading
import sys
import os
import socket
import hashlib
import tempfile
import re
import warnings

from fnmatch import translate
from re import match
from time import time, sleep
from typing import Any, Union, Dict, List, Tuple
from bs4 import BeautifulSoup

from ..core.base_recipe import BaseRecipe
from ..core.base_monitor import BaseMonitor
from ..core.base_pattern import BasePattern
from ..core.meow import EVENT_KEYS, valid_meow_dict
from ..core.rule import Rule
from ..core.vars import VALID_RECIPE_NAME_CHARS, \
    VALID_VARIABLE_NAME_CHARS, FILE_EVENTS, FILE_CREATE_EVENT, \
    FILE_MODIFY_EVENT, FILE_MOVED_EVENT, DEBUG_INFO, DIR_EVENTS, \
    FILE_RETROACTIVE_EVENT, SHA256, VALID_REGEX_CHARS, FILE_CLOSED_EVENT, \
    DIR_RETROACTIVE_EVENT, EVENT_PATH, DEBUG_DEBUG
from ..functionality.debug import setup_debugging, print_debug
from ..functionality.hashing import get_hash
from ..functionality.meow import create_event
from ..functionality.validation import check_type, valid_string, \
    valid_dict, valid_list, valid_dir_path
from ..patterns.file_event_pattern import WATCHDOG_EVENT_KEYS

SERVER = socket.gethostbyname(socket.gethostname())

from ..patterns.file_event_pattern import create_watchdog_event

# Message formats
HTML = "html"
NONE = "none"
MSG_FORMATS = [
    HTML,
    NONE
]

def create_socket_event(temp_path:str, rule:Any, base:str, time:float, 
                        extras:Dict[Any,Any]={})->Dict[Any,Any]:
    with open(temp_path, "rb") as file_pointer:
        file_hash = hashlib.sha256(file_pointer.read()).hexdigest()

    if base not in temp_path:
        raise ValueError("Cannot convert from socket event to watchdog event "
                         f"if temp file '{temp_path}' not placed in base "
                         f"directory '{base}'.")

    return create_watchdog_event(
        temp_path[temp_path.index(base):], 
        rule, 
        base,
        time, 
        file_hash, 
        extras=extras
    )


def valid_socket_event(event):
    valid_meow_dict(event, "Socket file event", WATCHDOG_EVENT_KEYS)

class SocketEventPattern(BasePattern):
    triggering_addr: str

    triggering_ports: List[int]

    triggering_format: str

    triggering_msg: Any

    def __init__(self, name:str, triggering_addr:str, triggering_ports:Union[int, List[int]], 
                 recipe:str, triggering_msg: Any, triggering_format:str=NONE, 
                 parameters:Dict[str,Any]={}, outputs:Dict[str,Any]={},
                 sweep:Dict[str,Any]={},notifications:Dict[str,Any]={}, tracing:str=""):
        super().__init__(name, recipe, parameters=parameters, outputs=outputs, 
            sweep=sweep, notifications=notifications, tracing=tracing)
        self._is_valid_address(triggering_addr)
        self.triggering_addr = triggering_addr
        if not type(triggering_ports) == list:
            triggering_ports = [triggering_ports]
        self._is_valid_port(triggering_ports)
        self.triggering_ports = triggering_ports
        self._is_valid_message(triggering_msg)
        self.triggering_msg = triggering_msg
        self._is_valid_format(triggering_format)
        self.triggering_format = triggering_format

    def _is_valid_address(self, triggering_addr:str)->None:
        try:
            re.compile(triggering_addr)
        except re.error:
            raise ValueError (
                f"Address '{triggering_addr}' is not a valid regular expression."
            )

    def _is_valid_port(self, triggering_ports:List[int])->None:
        for port in triggering_ports:
            if not isinstance(port, int):
                raise ValueError (
                    f"Port '{port}' is not of type int."
                )
            elif not (0 < port < 65535):
                raise ValueError (
                    f"Port '{port}' is not valid."
                )
            elif port <= 1024:
                warnings.warn(f"Port '{port}' is using a reserved port.")

    def _is_valid_message(self, triggering_msg:Any)->None:
        pass

    def _is_valid_recipe(self, recipe:str)->None:
        valid_string(
            recipe, 
            VALID_RECIPE_NAME_CHARS,
            hint="SocketEventPattern.recipe"
        )
    
    def _is_valid_format(self, format:str)->None:
        if format not in MSG_FORMATS:
            raise ValueError(f"Invalid format '{format}'. Valid are: "
                            f"{MSG_FORMATS}")

    def _is_valid_parameters(self, parameters:Dict[str,Any])->None:
        valid_dict(
            parameters, 
            str, 
            Any, 
            strict=False, 
            min_length=0, 
            hint="SocketEventPattern.parameters"
        )
        for k in parameters.keys():
            valid_string(
                k, 
                VALID_VARIABLE_NAME_CHARS,
                hint=f"SocketEventPattern.parameters[{k}]"
            )
    
    def _is_valid_output(self, outputs:Dict[str,str])->None:
        valid_dict(
            outputs, 
            str, 
            str, 
            strict=False, 
            min_length=0,
            hint="SocketEventPattern.outputs"
        )
        for k in outputs.keys():
            valid_string(
                k, 
                VALID_VARIABLE_NAME_CHARS,
                hint=f"SocketEventPattern.outputs[{k}]"
            )

    def assemble_params_dict(self, event:Dict[str,Any])->Dict[str,Any]|List[Dict[str,Any]]:
        base_params =  super().assemble_params_dict(event)
        return base_params




class SocketEventMonitor(BaseMonitor):
    # Directory for temporary files
    tmpfile_dir: str
    # List of temporary files
    tmpfiles: List[str]
    # Port monitered
    ports: List[int]
    # Socket connected to monitored port
    monitered_sockets: List[socket.socket]
    # Boolean to determine the status of the monitor
    _running: bool
    # List of connections
    connected_sockets: list[socket.socket]

    def __init__(self, tmpfile_dir:str, patterns:Dict[str,SocketEventPattern], 
                 recipes:Dict[str,BaseRecipe],ports:Union[int, List[int]], autostart=False,
                 name:str="")->None:
        super().__init__(patterns, recipes, name=name)
        self._is_valid_tempfile_dir(tmpfile_dir)
        self.tmpfile_dir = tmpfile_dir
        self.tmpfiles = []
        self._is_valid_port(ports)
        if not type(ports) == list:
            ports = [ports]
        self.ports = ports
        self._running = False
        self.connected_sockets = []
        self.monitered_sockets = []
        for port in self.ports:
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.monitered_sockets.append(new_socket)

        if autostart:
            self.start()

    def start(self):
        if not self._running:
            self._running = True
            for i in range(len(self.ports)):
                self.monitered_sockets[i].bind((SERVER, self.ports[i]))
                self.monitered_sockets[i].listen(1)
                threading.Thread(
                    target=self.main_loop,
                    args=(i,)
                ).start()

    def main_loop(self, i):
        while self._running:
            conn, addr = self.monitered_sockets[i].accept()
            self.connected_sockets.append(conn)
            threading.Thread(
                target=self.handle_connection,
                args=(conn, addr, i)
            ).start()

    def handle_connection(self, conn, addr, i):
        with conn:
            while self._running:
                msg = conn.recv(1024)
                if not msg:
                    return
                self.match(msg, addr, i)

    def stop(self):
        self._running = False
        for port in self.ports:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((SERVER, port))
        for sock in self.monitered_sockets:
            sock.close()
    
    def match(self, msg, addr, i):
        for rule in self._rules.values():
           matched_addr = re.search(rule.pattern.triggering_addr, addr[0])
           matched_format = self.format_check(rule, msg)
           matched_port = self.ports[i] in rule.pattern.triggering_ports
           if matched_addr and matched_port and matched_format:
                tmp_file = tempfile.NamedTemporaryFile(
                    "wb", delete=False, dir=self.tmpfile_dir
                )

                with open(tmp_file.name, "wb") as f:
                    f.write(msg)
                    f.close()

                self.tmpfiles.append(tmp_file.name[tmp_file.name.index(self.tmpfile_dir):])

                meow_event = create_socket_event(
                    tmp_file.name, rule, self.tmpfile_dir, time()
                )   
                self.send_event_to_runner(meow_event)


    def format_check(self, rule, msg)->bool:
        match rule.pattern.triggering_format:
            case "html":
                return self.HTML_validator(str(msg))
            case _:
                return True

    def _is_valid_tempfile_dir(self, tmpfile_dir):
        valid_dir_path(tmpfile_dir, must_exist=True)

    def _is_valid_port(self, port:int)->None:
        if not isinstance(port, int):
            raise ValueError (
                f"Port '{port}' is not of type int."
            )
        elif not (1023 < port < 49152):
            raise ValueError (
                f"Port '{port}' is not valid."
            )
        
    def _is_valid_patterns(self, patterns:Dict[str,SocketEventPattern])->None:
        valid_dict(patterns, str, SocketEventPattern, min_length=0, strict=False)

    def _is_valid_recipes(self, recipes:Dict[str,BaseRecipe])->None:
        valid_dict(recipes, str, BaseRecipe, min_length=0, strict=False)
    
    def _get_valid_pattern_types(self)->List[type]:
        return [SocketEventPattern]
    
    def _get_valid_recipe_types(self)->List[type]:
        return [BaseRecipe]

    def HTML_validator(self, msg: str):
        soup = BeautifulSoup(msg, 'html.parser')
        return msg == str(soup)