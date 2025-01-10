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

# TODO: double check; may need to import more
from ..patterns.file_event_pattern import create_watchdog_event

# Message formats
HTML = "html"
NONE = "none"
MSG_FORMATS = [
    HTML,
    NONE
]

# TODO: create socket file event (using watchdog probably)
def create_socket_event(temp_path:str, rule:Any, base:str, time:float, 
                        extras:Dict[Any,Any]={})->Dict[Any,Any]:
    # file_hash = get_hash(temp_path, SHA256)
    with open(temp_path, "rb") as f:
        print(f"creating event with file {temp_path} with content:")
        print(f.read())
    with open(temp_path, "rb") as file_pointer:
        file_hash = hashlib.sha256(file_pointer.read()).hexdigest()

    if base not in temp_path:
        raise ValueError("Cannot convert from socket event to watchdog event "
                         f"if temp file '{temp_path}' not placed in base "
                         f"directory '{base}'.")

    return create_watchdog_event(
        temp_path[temp_path.index(base):], 
        rule, 
        base,#tempfile.gettempdir(), 
        time, 
        file_hash, 
        extras=extras
    )


def valid_socket_event(event):
    valid_meow_dict(event, "Socket file event", WATCHDOG_EVENT_KEYS)

class SocketEventPattern(BasePattern):
    triggering_addr: str

    triggering_ports: List[int]

    triggering_format: str # TODO: expand this

    # Consider deleting this for now
    triggering_msg: Any

    # Triggering protocol

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

    # TODO: validate the address; should probably be a regular expression
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

    # TODO: validate the message
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

    # TODO: extend assemble_params; add path variable (but how does this relate to sockets?)
    def assemble_params_dict(self, event:Dict[str,Any])->Dict[str,Any]|List[Dict[str,Any]]:
        base_params =  super().assemble_params_dict(event)
        return base_params

    # possible TODO: keywords? the function get_additional_replacement_keywords?



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
                 name:str="")->None: # TODO: print, logging for debugging
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
        #self.monitered_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.monitered_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if autostart:
            self.start()

    # start monitoring the system, handle any connections
    def start(self):
        if not self._running:
            self._running = True
            for i in range(len(self.ports)):
                print(f"binding to {self.ports[i]}")
                self.monitered_sockets[i].bind((SERVER, self.ports[i]))
                self.monitered_sockets[i].listen(1)
                print("bind and listen good")
                threading.Thread(
                    target=self.main_loop,
                    args=(i,)
                ).start()

    # handle incoming connections/messages
    def main_loop(self, i):
        #print(f"binding to {self.port}")
        #self.monitered_socket.bind((SERVER, self.port))
        #self.monitered_socket.listen(1)
        #print("bind and listen good")
        while self._running:
            conn, addr = self.monitered_sockets[i].accept()
            self.connected_sockets.append(conn)
            threading.Thread(
                target=self.handle_connection,
                args=(conn, addr, i)
            ).start()

    # handle the actual connection, read the message
    def handle_connection(self, conn, addr, i):
        with conn:
            while self._running:
                msg = conn.recv(1024)
                if not msg:
                    return
                self.match(msg, addr, i)

    # stop the system monitoring
    def stop(self):
        '''
        for conn in self.connected_sockets:
            print("closing connected socket")
            conn.close()
        '''
        self._running = False
        for port in self.ports:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((SERVER, port))
            print(f"closing {port}")
        for sock in self.monitered_sockets:
            sock.close()
        print("closed all good")
    
    # TODO: given an event, determine a match based on patterns; send event to runner
    def match(self, msg, addr, i):
        print(msg)
        for rule in self._rules.values():
           # print(addr[0])
           matched_addr = re.search(rule.pattern.triggering_addr, addr[0])
           matched_format = self.format_check(rule, msg)
           # print(f"the addr[1] is {addr[1]}")
           print(f"The port receiving is {self.ports[i]}")
           matched_port = self.ports[i] in rule.pattern.triggering_ports
           if matched_addr and matched_port and matched_format:
                tmp_file = tempfile.NamedTemporaryFile(
                    "wb", delete=False, dir=self.tmpfile_dir
                )
                #print("BEFORE WRITING:")

                print(f"DOES THE TMP FILE EXIST? {os.path.exists(tmp_file.name)}")

                with open(tmp_file.name, "rb") as f:
                    print("BEFORE WRITING:")
                    print(f.read())
            
                with open(tmp_file.name, "wb") as f:
                    f.write(msg)
                    f.close()
                
                with open(tmp_file.name, "rb") as f:
                    print("AFTER WRITING:")
                    print(f.read())

                #print("AFTER WRITING:")
                #print(tmp_file.read())

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
        return msg == str(soup) # TODO: correct?