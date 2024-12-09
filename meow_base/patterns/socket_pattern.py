import glob
import threading
import sys
import os
import socket
import hashlib
import tempfile

from fnmatch import translate
from re import match
from time import time, sleep
from typing import Any, Union, Dict, List, Tuple

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

# TODO: create socket file event (using watchdog probably)
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
        base,#tempfile.gettempdir(), 
        time, 
        file_hash, 
        extras=extras
    )


def valid_socket_event(event):
    valid_meow_dict(event, "Socket file event", WATCHDOG_EVENT_KEYS)

class SocketEventPattern(BasePattern):
    triggering_port: int

    triggering_msg: Any

    def __init__(self, name:str, triggering_port:int, recipe:str, triggering_msg: Any, 
                 parameters:Dict[str,Any]={}, outputs:Dict[str,Any]={},sweep:Dict[str,Any]={},
                 notifications:Dict[str,Any]={}, tracing:str=""):
        super().__init__(name, recipe, parameters=parameters, outputs=outputs, 
            sweep=sweep, notifications=notifications, tracing=tracing)
        self._is_valid_port(triggering_port)
        self.triggering_port = triggering_port
        self._is_valid_message(triggering_msg)
        self.triggering_msg = triggering_msg
        # possible TODO: validate and assign any potential event mask

    def _is_valid_port(self, triggering_port:int)->None:
        if not isinstance(triggering_port, int):
            raise ValueError (
                f"Port '{triggering_port}' is not of type int."
            )
        elif not (1023 < triggering_port < 49152):
            raise ValueError (
                f"Port '{triggering_port}' is not valid."
            )

    # TODO: validate the message
    def _is_valid_message(self, triggering_msg:str)->None:
        pass
        
    def _is_valid_recipe(self, recipe:str)->None:
        valid_string(
            recipe, 
            VALID_RECIPE_NAME_CHARS,
            hint="SocketEventPattern.recipe"
        )
    
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
    # Port monitered
    port: int
    # Socket connected to monitored port
    monitered_socket: socket
    # Boolean to determine the status of the monitor
    _running: bool
    def __init__(self, tmpfile_dir:str, patterns:Dict[str,SocketEventPattern], 
                 recipes:Dict[str,BaseRecipe],port:int, autostart=False,
                 name:str="")->None: # TODO: print, logging for debugging
        super().__init__(patterns, recipes, name=name)
        self._is_valid_tempfile_dir(tmpfile_dir)
        self.tmpfile_dir = tmpfile_dir
        self._is_valid_port(port)
        self.port = port
        self._running = False
        self.monitered_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if autostart:
            self.start()

    # start monitoring the system, handle any connections
    def start(self):
        if not self._running:
            threading.Thread(target=self.main_loop).start()

    # handle incoming connections/messages
    def main_loop(self):
        self.monitered_socket.bind((SERVER, self.port))
        self.monitered_socket.listen(1)
        self._running = True
        while self._running:
            conn, _ = self.monitered_socket.accept()
            threading.Thread(
                target=self.handle_connection,
                args=(conn,)
            ).start()

    # handle the actual connection, read the message
    def handle_connection(self, conn):
        with conn:
            while self._running:
                msg = conn.recv(1024)
                if not msg:
                    return
                tmp_file = tempfile.NamedTemporaryFile(
                        "wb", delete=False, dir=self.tmpfile_dir
                )
                tmp_file.write(msg)

                meow_event = create_socket_event(
                        tmp_file.name, list(self._rules.values())[0], self.tmpfile_dir, time()
                )
                self.match(meow_event)

    # stop the system monitoring
    def stop(self):
        self._running = False
        self.monitered_socket.close()
    
    # TODO: given an event, determine a match based on patterns; send event to runner
    def match(self, event):
        self.send_event_to_runner(event)

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

# TODO: Socket monitor
class SocketEventMonitorOld(BaseMonitor):
    # The directory of the temporary message file(s)
    base_dir: str
    # Port listened on
    triggering_port: int
    # The socket listened to
    triggering_socket: socket
    # List of temporary files TODO: consider deleting this if it's not used
    # temp_files: List[str]
    # Bool indicating status of socket
    _stopped: bool
    # print target
    _print_target:Any
    # debug level
    debug_level:int
    def __init__(self, base_dir:str, patterns:Dict[str,SocketEventPattern], 
                 recipes:Dict[str,BaseRecipe],triggering_port:int, autostart=False,
                 name:str="", print:Any=sys.stdout, logging:int=0)->None:
        super().__init__(patterns, recipes, name=name)
        self._is_valid_base_dir(base_dir)
        self.base_dir = base_dir
        self._is_valid_port(triggering_port)
        self.triggering_port = triggering_port
        # self.temp_files = []
        self._print_target, self.debug_level = setup_debugging(print, logging)
        self.triggering_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._stopped = True
        print_debug(self._print_target, self.debug_level, 
            "Created new WatchdogMonitor instance", DEBUG_INFO)
        
        if autostart:
            self.start()
        
    def _is_valid_base_dir(self, base_dir):
        valid_dir_path(base_dir, must_exist=True)

    def _is_valid_port(self, triggering_port:int)->None:
        if not isinstance(triggering_port, int):
            raise ValueError (
                f"Port '{triggering_port}' is not of type int."
            )
        elif not (1023 < triggering_port < 49152):
            raise ValueError (
                f"Port '{triggering_port}' is not valid."
            )

    def start(self):
        if self._stopped:
            threading.Thread(
                target=self.main_loop
            ).start()
        else:
            # TODO: some error here
            pass

    def main_loop(self):
        self.triggering_socket.bind((SERVER, self.triggering_port))
        self.triggering_socket.listen(1)
        self._stopped = False
        while not self._stopped:
            try:
                conn, _ = self.triggering_socket.accept()
            except socket.timeout:
                pass
            except OSError:
                if self._stopped:
                    break
                else:
                    raise
            except:
                raise
            else:
                self._connected = True
                threading.Thread(
                    target=self.handle_event,
                    args=(conn, time())
                ).start()

    def stop(self):
        self._stopped = True
        self._connected = False
        self.triggering_socket.close()

    def handle_event(self, conn, ttime):
        with conn:
            while self._connected:
                msg = conn.recv(1024)
                print(f"received: {msg}")
                if not msg:
                    break
                tmp_file = tempfile.NamedTemporaryFile(
                    "wb", delete=False, dir=self.base_dir
                )
                tmp_file.write(msg)

                meow_event = create_socket_event(
                    tmp_file.name, list(self._rules.values())[0], self.base_dir, time()
                )
                self.match(meow_event)

    # Does a given event match the current rules.
    def match(self, event)->None:
        self.send_event_to_runner(event)

    def _is_valid_patterns(self, patterns:Dict[str,SocketEventPattern])->None:
        valid_dict(patterns, str, SocketEventPattern, min_length=0, strict=False)
    
    def _is_valid_recipes(self, recipes:Dict[str,BaseRecipe])->None:
        valid_dict(recipes, str, BaseRecipe, min_length=0, strict=False)
    
    def _get_valid_pattern_types(self)->List[type]:
        return [SocketEventPattern]
    
    def _get_valid_recipe_types(self)->List[type]:
        return [BaseRecipe]