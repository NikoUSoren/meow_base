
"""
This file contains tests for the implementation of network events
in the MEOW framework. See the file socket_pattern.py for details
regarding this implementation.

Author(s): Nikolaj Sørensen
"""

import io
import os
import socket
import tempfile
import unittest
import warnings

from multiprocessing import Pipe
from time import sleep, time
from watchdog.events import FileSystemEvent

from ..meow_base.core.vars import FILE_CREATE_EVENT, EVENT_TYPE, \
    EVENT_RULE, EVENT_PATH, SWEEP_START, META_FILE, \
    SWEEP_JUMP, SWEEP_STOP, DIR_EVENTS, JOB_ERROR
from ..meow_base.functionality.file_io import make_dir, read_yaml
from ..meow_base.functionality.meow import create_rule, assemble_patterns_dict, \
    assemble_recipes_dict
from ..meow_base.patterns.file_event_pattern import FileEventPattern, \
    WatchdogMonitor, WatchdogEventHandler, _DEFAULT_MASK, WATCHDOG_HASH, \
    WATCHDOG_BASE, EVENT_TYPE_WATCHDOG, WATCHDOG_EVENT_KEYS, \
    create_watchdog_event
from ..meow_base.patterns.socket_event_pattern import SocketPattern, \
    SocketMonitor, create_socket_file_event
from ..meow_base.patterns.socket_pattern import SocketEventPattern, \
    SocketEventMonitor, create_socket_event
from ..meow_base.recipes.jupyter_notebook_recipe import JupyterNotebookRecipe
from ..meow_base.recipes.python_recipe import PythonRecipe
from .shared import SharedTestPattern, SharedTestRecipe, \
    BAREBONES_NOTEBOOK, TEST_MONITOR_BASE, COUNTING_PYTHON_SCRIPT, \
    APPENDING_NOTEBOOK, setup, teardown, check_port_in_use, \
    check_shutdown_port_in_timeout, TEST_JOB_QUEUE, TEST_JOB_OUTPUT, \
    BAREBONES_PYTHON_SCRIPT, COMPLETE_PYTHON_SCRIPT
from ..meow_base.conductors import LocalPythonConductor
from ..meow_base.recipes.python_recipe import PythonHandler, PythonRecipe
from ..meow_base.core.runner import MeowRunner

HEADER_LENGTH = 64
TEST_PORT = 8080
TEST_SERVER = socket.gethostbyname(socket.gethostname())

def patterns_equal(tester, pattern_one, pattern_two):
    tester.assertEqual(pattern_one.name, pattern_two.name)
    tester.assertEqual(pattern_one.recipe, pattern_two.recipe)
    tester.assertEqual(pattern_one.parameters, pattern_two.parameters)
    tester.assertEqual(pattern_one.outputs, pattern_two.outputs)
    tester.assertEqual(pattern_one.sweep, pattern_two.sweep)

    if type(pattern_one) != type(pattern_two):
        raise TypeError("Expected matching pattern types. Got "
                        f"{type(pattern_one)} and {type(pattern_two)}")
    
    if type(pattern_one) == FileEventPattern:
        tester.assertEqual(pattern_one.triggering_path, 
            pattern_two.triggering_path)
        tester.assertEqual(pattern_one.triggering_file, 
            pattern_two.triggering_file)
        tester.assertEqual(pattern_one.event_mask, pattern_two.event_mask)
    elif type(pattern_one) == SocketPattern:
        tester.assertEqual(pattern_one.triggering_port, 
            pattern_two.triggering_port)
    else:
        raise TypeError(f"Unknown pattern type {type(pattern_one)}")

def recipes_equal(tester, recipe_one, recipe_two):
    tester.assertEqual(recipe_one.name, recipe_two.name)
    tester.assertEqual(recipe_one.recipe, recipe_two.recipe)
    tester.assertEqual(recipe_one.parameters, recipe_two.parameters)
    tester.assertEqual(recipe_one.requirements, recipe_two.requirements)
    tester.assertEqual(recipe_one.source, recipe_two.source)

class SocketEventPatternTests(unittest.TestCase):
    def setUp(self)->None:
        super().setUp()
        setup()

    def tearDown(self)->None:
        super().tearDown()
        teardown()

    # Test creating a SocketEventPattern
    def testSocketEventPatternCreationMinimum(self)->None:
        SocketEventPattern("name", TEST_SERVER, TEST_PORT, "recipe", "msg")

    # Test SocketEventPattern not created with empty name
    def testSocketEventPatternCreationEmptyName(self)->None:
        with self.assertRaises(ValueError):
            SocketEventPattern("", TEST_SERVER, TEST_PORT, "recipe", "msg")

    # Test SocketEventPattern not created with empty recipe
    def testSocketPatternCreationEmptyRecipe(self)->None:
        with self.assertRaises(ValueError):
            SocketEventPattern("name", TEST_SERVER, TEST_PORT, "", "msg")

    # Test SocketEventPattern not created with invalid name
    def testSocketEventPatternCreationInvalidName(self)->None:
        with self.assertRaises(ValueError):
            SocketEventPattern("@name", TEST_SERVER, TEST_PORT, "recipe", "msg")
    
    # Test SocketEventPattern not created with invalid recipe
    def testSocketEventPatternCreationInvalidRecipe(self)->None:
        with self.assertRaises(ValueError):
            SocketEventPattern("name", TEST_SERVER, TEST_PORT, "@recipe", "msg")

    # Test SocketEventPattern not created with invalid port
    def testSocketEventPatternCreationInvalidPort(self)->None:
        with self.assertRaises(ValueError):
            SocketEventPattern("name", TEST_SERVER, -1, "recipe", "msg")

    def testSocketEventPatternCreationInvalidAddr(self)->None:
        with self.assertRaises(ValueError):
            SocketEventPattern("name", "[", TEST_PORT, "recipe", "msg")
    
    # Test SocketEventPattern not created with invalid format
    def testSocketEventPatternCreationInvalidFormat(self)->None:
        with self.assertRaises(ValueError):
            SocketEventPattern(
                "name", 
                TEST_SERVER, 
                TEST_PORT, 
                "recipe", 
                "msg", 
                triggering_format="notrealformat")

    # Test SocketEventPattern created with valid name
    def testSocketEventPatternSetupName(self)->None:
        name = "name"
        sep = SocketEventPattern(name, TEST_SERVER, TEST_PORT, "recipe", "msg")
        self.assertEqual(sep.name, name)

    # Test SocketEventPattern created with valid port
    def testSocketEventPatternSetupPort(self)->None:
        sep = SocketEventPattern("name", TEST_SERVER, TEST_PORT, "recipe", "file")
        self.assertEqual(sep.triggering_ports, [TEST_PORT])
    
    def testSocketEventPatternSetupPortList(self)->None:
        port_list = [TEST_PORT, TEST_PORT + 1]
        sep = SocketEventPattern("name", TEST_SERVER, port_list, "recipe", "file")
        self.assertEqual(sep.triggering_ports, port_list)

    def testSocketEventPatternSetupPortWarning(self)->None:
        with self.assertWarns(Warning):
            SocketEventPattern("name", TEST_SERVER, 500, "recipe", "file")

    # Test SocketEventPattern created with valid recipe
    def testSocketEventPatternSetupRecipe(self)->None:
        recipe = "recipe"
        sep = SocketEventPattern("name", TEST_SERVER, TEST_PORT, recipe, "msg")
        self.assertEqual(sep.recipe, recipe)

    # SetupParamenters
    def testSocketEventPatternSetupParementers(self)->None:
        parameters = {
            "a": 1,
            "b": True
        }
        sep = SocketEventPattern(
            "name", TEST_SERVER, TEST_PORT, "recipe", "msg", parameters=parameters)
        self.assertEqual(sep.parameters, parameters)

    # SetupOutputs
    def testSocketEventPatternSetupOutputs(self)->None:
        outputs = {
            "a": "a",
            "b": "b"
        }
        sep = SocketEventPattern(
            "name", TEST_SERVER, TEST_PORT, "recipe", "msg", outputs=outputs)
        self.assertEqual(sep.outputs, outputs)

    # Test SocketEventPattern created with valid parameter sweep
    def testSocketEventPatternSweep(self)->None:
        sweeps = {
            'first':{
                SWEEP_START: 0,
                SWEEP_STOP: 3,
                SWEEP_JUMP: 1
            },
            'second':{
                SWEEP_START: 10,
                SWEEP_STOP: 0,
                SWEEP_JUMP: -2
            }
        }
        sep = SocketEventPattern("name", TEST_SERVER, TEST_PORT, "recipe", "msg", 
                                 sweep=sweeps)
        self.assertEqual(sep.sweep, sweeps)

        bad_sweep = {
            'first':{
                SWEEP_START: 0,
                SWEEP_STOP: 3,
                SWEEP_JUMP: -1
            },
        }
        with self.assertRaises(ValueError):
            fep = SocketEventPattern("name", TEST_SERVER, TEST_PORT, "recipe", "file", 
                sweep=bad_sweep)

        bad_sweep = {
            'second':{
                SWEEP_START: 10,
                SWEEP_STOP: 0,
                SWEEP_JUMP: 1
            }
        }
        with self.assertRaises(ValueError):
            fep = SocketEventPattern("name", TEST_SERVER, TEST_PORT, "recipe", "file", 
                sweep=bad_sweep)


class SocketEventMonitorTests(unittest.TestCase):
    def setUp(self)->None:
        super().setUp()
        setup()

    def tearDown(self)->None:
        super().tearDown()
        teardown()

    def testCreateSocketEvent(self)->None:
        pattern = SocketEventPattern(
            "pattern",
            TEST_SERVER,
            TEST_PORT,
            "recipe_one",
            "msg",
            parameters={
                "extra":"A line from a test Pattern",
                "outfile":"result_path"
            })
        recipe = JupyterNotebookRecipe(
            "recipe_one", APPENDING_NOTEBOOK)
        
        rule = create_rule(pattern, recipe)

        tmp_file = tempfile.NamedTemporaryFile(
            "wb", delete=True, dir=TEST_MONITOR_BASE
        )
        tmp_file.write(b"data")

        with self.assertRaises(TypeError):
            create_socket_event(tmp_file.name, rule)

        event = create_socket_event(tmp_file.name, rule, TEST_MONITOR_BASE, time())

        tmp_file.close()

        self.assertEqual(type(event), dict)
        self.assertEqual(len(event.keys()), len(WATCHDOG_EVENT_KEYS))
        for key, value in WATCHDOG_EVENT_KEYS.items():
            self.assertTrue(key in event.keys())
            self.assertIsInstance(event[key], value)
        self.assertEqual(event[EVENT_TYPE], EVENT_TYPE_WATCHDOG)
        self.assertEqual(
            event[EVENT_PATH], 
            tmp_file.name[tmp_file.name.index(TEST_MONITOR_BASE):]
        )
        self.assertEqual(event[EVENT_RULE], rule)

        tmp_file2 = tempfile.NamedTemporaryFile(
            "wb", delete=True, dir=TEST_MONITOR_BASE
        )
        tmp_file2.write(b"data")
        
        event = create_socket_event(
            tmp_file2.name,
            rule,
            TEST_MONITOR_BASE,
            time(),
            extras={"a":1}
        )

        tmp_file2.close()

        self.assertEqual(type(event), dict)
        self.assertTrue(EVENT_TYPE in event.keys())
        self.assertTrue(EVENT_PATH in event.keys())
        self.assertTrue(EVENT_RULE in event.keys())
        self.assertEqual(len(event.keys()), len(WATCHDOG_EVENT_KEYS)+1)
        for key, value in WATCHDOG_EVENT_KEYS.items():
            self.assertTrue(key in event.keys())
            self.assertIsInstance(event[key], value)
        self.assertEqual(event[EVENT_TYPE], EVENT_TYPE_WATCHDOG)
        self.assertEqual(
            event[EVENT_PATH], 
            tmp_file2.name[tmp_file2.name.index(TEST_MONITOR_BASE):]
        )
        self.assertEqual(event[EVENT_RULE], rule)
        self.assertEqual(event["a"], 1)

    def testSocketMonitorMinimum(self)->None:
        SocketEventMonitor(TEST_MONITOR_BASE, {}, {}, TEST_PORT)

    
    def testSocketMonitorNaming(self)->None:
        test_name = "test_name"
        monitor = SocketEventMonitor(TEST_MONITOR_BASE, {}, {}, TEST_PORT, name=test_name)
        self.assertEqual(monitor.name, test_name)

        monitor = SocketEventMonitor(TEST_MONITOR_BASE, {}, {}, TEST_PORT+1)
        self.assertTrue(monitor.name.startswith("monitor_"))

    
    def testSocketMonitorEventIdentificaion(self)->None:
        from_monitor_reader, from_monitor_writer = Pipe()

        pattern_one = SocketEventPattern(
            "pattern_one", "(.*)", TEST_PORT, "recipe_one", "message_one")
        recipe = JupyterNotebookRecipe(
            "recipe_one", BAREBONES_NOTEBOOK)
        
        patterns = {
            pattern_one.name: pattern_one,
        }
        recipes = {
            recipe.name: recipe,
        }

        sm = SocketEventMonitor(
            TEST_MONITOR_BASE, patterns, recipes, TEST_PORT)
        sm.to_runner_event = from_monitor_writer

        rules = sm.get_rules()

        self.assertEqual(len(rules), 1)
        rule = rules[list(rules.keys())[0]]

        sm.start()

        while not sm._running:
            sleep(1)
        
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((TEST_SERVER, TEST_PORT))
        test_socket.sendall(b'test')
        test_socket.close()

        if from_monitor_reader.poll(3):
            event_message = from_monitor_reader.recv()
        else:
            event_message = None

        self.assertIsNotNone(event_message)
        event = event_message
        self.assertIsNotNone(event)
        self.assertEqual(type(event), dict)
        self.assertTrue(EVENT_TYPE in event.keys())
        self.assertTrue(EVENT_PATH in event.keys())
        self.assertTrue(WATCHDOG_BASE in event.keys())
        self.assertTrue(EVENT_RULE in event.keys())
        self.assertEqual(event[EVENT_TYPE], EVENT_TYPE_WATCHDOG)
        self.assertEqual(event[EVENT_PATH], sm.tmpfiles[0])
        self.assertEqual(event[WATCHDOG_BASE], TEST_MONITOR_BASE)
        self.assertEqual(event[EVENT_RULE].name, rule.name)
        self.assertTrue(os.path.exists(event[EVENT_PATH]))
        
        sm.stop()
    
    def testSocketMonitorPortMismatch(self)->None:
        from_monitor_reader, from_monitor_writer = Pipe()

        pattern_one = SocketEventPattern(
            "pattern_one", "(.*)", TEST_PORT+1, "recipe_one", "message_one")
        recipe = JupyterNotebookRecipe(
            "recipe_one", BAREBONES_NOTEBOOK)
        
        patterns = {
            pattern_one.name: pattern_one,
        }
        recipes = {
            recipe.name: recipe,
        }

        sm = SocketEventMonitor(
            TEST_MONITOR_BASE, patterns, recipes, TEST_PORT)
        sm.to_runner_event = from_monitor_writer

        sm.start()

        while not sm._running:
            sleep(1)

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((TEST_SERVER, TEST_PORT))

        test_socket.sendall(b'test')
        test_socket.close()

        if from_monitor_reader.poll(3):
            event_message = from_monitor_reader.recv()
        else:
            event_message = None

        self.assertIsNone(event_message)

        sm.stop()
    

    def testSocketMonitorPortList(self)->None:
        from_monitor_reader, from_monitor_writer = Pipe()

        pattern_one = SocketEventPattern(
            "pattern_one", "(.*)", [TEST_PORT+1, TEST_PORT], "recipe_one", "message_one")
        recipe = JupyterNotebookRecipe(
            "recipe_one", BAREBONES_NOTEBOOK)
        
        patterns = {
            pattern_one.name: pattern_one,
        }
        recipes = {
            recipe.name: recipe,
        }

        sm = SocketEventMonitor(
            TEST_MONITOR_BASE, patterns, recipes, TEST_PORT)
        sm.to_runner_event = from_monitor_writer

        rules = sm.get_rules()

        self.assertEqual(len(rules), 1)
        rule = rules[list(rules.keys())[0]]

        sm.start()

        while not sm._running:
            sleep(1)

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((TEST_SERVER, TEST_PORT))

        test_socket.sendall(b'test')
        test_socket.close()

        if from_monitor_reader.poll(3):
            event_message = from_monitor_reader.recv()
        else:
            event_message = None

        self.assertIsNotNone(event_message)
        event = event_message
        self.assertIsNotNone(event)
        self.assertEqual(type(event), dict)
        self.assertTrue(EVENT_TYPE in event.keys())
        self.assertTrue(EVENT_PATH in event.keys())
        self.assertTrue(WATCHDOG_BASE in event.keys())
        self.assertTrue(EVENT_RULE in event.keys())
        self.assertEqual(event[EVENT_TYPE], EVENT_TYPE_WATCHDOG)
        self.assertEqual(event[EVENT_PATH], sm.tmpfiles[0])
        self.assertEqual(event[WATCHDOG_BASE], TEST_MONITOR_BASE)
        self.assertEqual(event[EVENT_RULE].name, rule.name)
        self.assertTrue(os.path.exists(event[EVENT_PATH]))

        sm.stop()
    
    def testSocketMonitorHTMLValidation(self)->None:
        from_monitor_reader, from_monitor_writer = Pipe()

        pattern_one = SocketEventPattern(
            "pattern_one", "(.*)", TEST_PORT, "recipe_one", "message_one", triggering_format="html")
        recipe = JupyterNotebookRecipe(
            "recipe_one", BAREBONES_NOTEBOOK)
        
        patterns = {
            pattern_one.name: pattern_one,
        }
        recipes = {
            recipe.name: recipe,
        }

        sm = SocketEventMonitor(
            TEST_MONITOR_BASE, patterns, recipes, TEST_PORT)
        sm.to_runner_event = from_monitor_writer

        rules = sm.get_rules()

        self.assertEqual(len(rules), 1)
        rule = rules[list(rules.keys())[0]]

        sm.start()

        while not sm._running:
            sleep(1)

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((TEST_SERVER, TEST_PORT))

        test_socket.sendall(b'<html></html>')
        test_socket.close()

        if from_monitor_reader.poll(3):
            event_message = from_monitor_reader.recv()
        else:
            event_message = None

        self.assertIsNotNone(event_message)
        event = event_message
        self.assertIsNotNone(event)
        self.assertEqual(type(event), dict)
        self.assertTrue(EVENT_TYPE in event.keys())
        self.assertTrue(EVENT_PATH in event.keys())
        self.assertTrue(WATCHDOG_BASE in event.keys())
        self.assertTrue(EVENT_RULE in event.keys())
        self.assertEqual(event[EVENT_TYPE], EVENT_TYPE_WATCHDOG)
        self.assertEqual(event[EVENT_PATH], sm.tmpfiles[0])
        self.assertEqual(event[WATCHDOG_BASE], TEST_MONITOR_BASE)
        self.assertEqual(event[EVENT_RULE].name, rule.name)
        self.assertTrue(os.path.exists(event[EVENT_PATH]))

        sm.stop()
    
    def testSocketMonitorHTMLValidationInvalid(self)->None:
        from_monitor_reader, from_monitor_writer = Pipe()

        pattern_one = SocketEventPattern(
            "pattern_one", "(.*)", TEST_PORT, "recipe_one", "message_one", triggering_format="html")
        recipe = JupyterNotebookRecipe(
            "recipe_one", BAREBONES_NOTEBOOK)
        
        patterns = {
            pattern_one.name: pattern_one,
        }
        recipes = {
            recipe.name: recipe,
        }

        sm = SocketEventMonitor(
            TEST_MONITOR_BASE, patterns, recipes, TEST_PORT)
        sm.to_runner_event = from_monitor_writer

        sm.start()

        while not sm._running:
            sleep(1)

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((TEST_SERVER, TEST_PORT))

        test_socket.sendall(b'<html>')
        test_socket.close()

        if from_monitor_reader.poll(3):
            event_message = from_monitor_reader.recv()
        else:
            event_message = None

        self.assertIsNone(event_message)

        sm.stop()

class SocketEventTests(unittest.TestCase):
    def setUp(self)->None:
        super().setUp()
        setup()

    def tearDown(self)->None:
        super().tearDown()
        teardown()

    def testMeowRunnerSetup(self)->None:
        monitor = SocketEventMonitor(TEST_MONITOR_BASE, {}, {}, TEST_PORT)

        handler = PythonHandler(pause_time=0)

        conductor = LocalPythonConductor(pause_time=0)

        runner = MeowRunner(monitor, handler, conductor)

        self.assertIsInstance(runner.monitors, list)
        for m in runner.monitors:
            self.assertIsInstance(m, SocketEventMonitor)
    
    def testPythonExecution(self)->None:
        pattern_one = SocketEventPattern(
            "pattern_one", "(.*)", TEST_PORT, "recipe_one", "message_one")
        recipe = PythonRecipe(
            "recipe_one", BAREBONES_PYTHON_SCRIPT)
        
        patterns = {
            pattern_one.name: pattern_one,
        }
        recipes = {
            recipe.name: recipe,
        }

        monitor = SocketEventMonitor(TEST_MONITOR_BASE, patterns, recipes, TEST_PORT)

        handler = PythonHandler(job_queue_dir=TEST_JOB_QUEUE)

        conductor = LocalPythonConductor(pause_time=2)

        runner = MeowRunner(monitor, handler, conductor, 
                            job_queue_dir=TEST_JOB_QUEUE, job_output_dir=TEST_JOB_OUTPUT)

        conductor_to_test_conductor, conductor_to_test_test = Pipe(duplex=True)
        test_to_runner_runner, test_to_runner_test = Pipe(duplex=True)

        runner.conductors[0].to_runner_job = conductor_to_test_conductor

        for i in range(len(runner.job_connections)):
            _, obj = runner.job_connections[i]

            if obj == runner.conductors[0]:
                runner.job_connections[i] = (test_to_runner_runner, runner.job_connections[i][1])
                
        runner.start()

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((TEST_SERVER, TEST_PORT))
        test_socket.sendall(b'test')
        test_socket.close()

        loops = 0
        while loops < 5:
            # Initial prompt
            if conductor_to_test_test.poll(5):
                msg = conductor_to_test_test.recv()
            else:
                raise Exception("Timed out")        
            self.assertEqual(msg, 1)
            test_to_runner_test.send(msg)

            # Reply
            if test_to_runner_test.poll(5):
                msg = test_to_runner_test.recv()
            else:
                raise Exception("Timed out")        
            job_dir = msg
            conductor_to_test_test.send(msg)

            if isinstance(job_dir, str):
                # Prompt again once complete
                if conductor_to_test_test.poll(5):
                    msg = conductor_to_test_test.recv()
                else:
                    raise Exception("Timed out")        
                self.assertEqual(msg, 1)
                loops = 5
            
            loops += 1

        job_dir = job_dir.replace(TEST_JOB_QUEUE, TEST_JOB_OUTPUT)
        self.assertTrue(os.path.exists(job_dir))

        runner.stop()

        metafile = os.path.join(job_dir, META_FILE)
        status = read_yaml(metafile)

        self.assertNotIn(JOB_ERROR, status)