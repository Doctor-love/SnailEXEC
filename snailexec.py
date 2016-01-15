#!/usr/bin/env python

'''SnailEXEC - Execute shell commands and output the results to JSON'''

developers = ['Joel Rangsmo <joel@rangsmo.se>']
description = __doc__
version = '0.3.1'
license = 'GPLv2'

try:
    import io
    import os
    import re
    import json
    import glob
    import time
    import getpass
    import logging
    import argparse
    import functools
    import subprocess
    import logging.handlers

    # PyInstaller requires explicit import of exit
    from sys import exit

except ImportError as missing:
    print(
        'UNKNOWN - Could not import all required modules: "%s".\n' % missing +
        'The script requires Python 2.7 or 2.6 with the "argparse" module\n'
        'Installation with PIP: "pip install argparse"')

    exit(3)


logger = logging.getLogger('snailexec')

# -----------------------------------------------------------------------------
# Exception related code

class SnailEXECError(Exception):
    '''All SnailExec related exceptions inherit from this one'''

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class ParseError(SnailEXECError):
    '''Exceptions related to parsing of command definitions and files'''


def json_guarded(func):
    '''Decorator that makes sure no exception generates non-JSON output'''

    @functools.wraps(func)
    def wrapper(*args, **kwds):
        # Converts all unhandled exceptions to JSON except SystemExit 

        try:
            return func(*args, **kwds)

        except SystemExit as exit_code:
            exit(int(str(exit_code)))
        
        except KeyboardInterrupt:
            exit_program(msg='SnailEXEC was interrupted by keyboard')

        except Exception as error_msg:
            # Exits the application with JSON output

            exit_program(
                msg='SnailEXEC generated an unhandled exception: "%s"'
                % error_msg)

    return wrapper

# -----------------------------------------------------------------------------
# Application exit related code

def exit_program(
    status='ERROR', msg='', tag='',
    results_version=1, results=[], output_file=None):
    
    '''Outputs status and results to stdout or file and exits the program'''

    logger.debug(
        'Exiting with status "%s", message "%s", '
        'tag "%s", results version %i and result data "%s"'
        % (status, msg, tag, results_version, str(results)))

    if output_file:
        logger.debug('Saving JSON output to file "%s"' % output_file)

    else:
        logger.debug('Printing output to stdout')

    output = {
        'status': status, 'msg': msg, 'tag': tag,
        'results_version': results_version, 'results': results}

    try:
        output = json.dumps(output, ensure_ascii=False)

        if output_file:
            file_object = io.open(output_file, 'w', encoding='utf-8')
            file_object.write(unicode(output))

            logger.debug('Successfully written output to "%s"' % output_file)

            file_object.close()

        else:
            print(unicode(output))

    except IOError as error_msg:
        logger.error(
            'Failed to write JSON data to output file "%s": "%s"'
            % (output_file, error_msg))

    except ValueError as error_msg:
        logger.error('Failed to generate JSON for output: "%s"' % error_msg)

    except Exception as error_msg:
        logger.error('Failed to generate output data: "%s"' % error_msg)

    if status == 'ERROR':
        exit_code = 1

    elif status == 'OK':
        exit_code = 0

    else:
        logger.error('Status code "%s" is unknown' % str(status))
        exit_code = 1

    exit(exit_code)

# -----------------------------------------------------------------------------
# Argument parsing related code

def expand_glob(glob_string):
    '''Expands a shell glob and returns a list of matching files'''

    try:
        matches = glob.glob(glob_string)

    except Exception as error_msg:
        raise argparse.ArgumentTypeError(
            'Failed to expand glob "%s": "%s"' % (glob_string, error_msg))

    if not len(matches):
        raise argparse.ArgumentTypeError(
            'Found no files matching shell glob "%s"' % glob_string)

    return matches

def parse_args(description=None, version=None, developers=None, license=None):
    '''Parses commandline arguments provided by the user'''

    parser = argparse.ArgumentParser(
        description=description,
        epilog=(
            'Developed by %s - licensed under %s!'
            % (', '.join(developers), license)))

    # Variables for common strings in help text
    cbu = '(can be used multiple times)'

    # -------------------------------------------------------------------------
    parser_source = parser.add_argument_group(title='Command source options')

    parser_source.add_argument(
        '-c', '--command', dest='commands',
        help='Result name and command to be executed %s' % cbu,
        action='append', metavar=('"test_x"', '"/bin/prog -p 1"'),
        nargs=2, type=str)

    parser_source.add_argument(
        '-j', '--json', dest='json_files',
        help='JSON file with commands to be executed %s' % cbu,
        action='append', metavar='/path/to/cmd.json', type=str)

    parser_source.add_argument(
        '-J', '--json-glob', dest='json_globs',
        help='Shell glob for JSON files with commands to be executed %s' % cbu,
        action='append', metavar='"/path/to/*.json"',
        type=expand_glob, default=[])

    parser_source.add_argument(
        '-n', '--nrpe', dest='nrpe_files',
        help='NRPE file with commands to be executed %s' % cbu,
        action='append', metavar='/path/to/commands.cfg', type=str)

    parser_source.add_argument(
        '-N', '--nrpe-glob', dest='nrpe_globs',
        help='Shell glob for NRPE files with commands to be executed %s' % cbu,
        action='append', metavar='"/path/to/*.cfg"',
        type=expand_glob, default=[])

    # -------------------------------------------------------------------------
    parser_output = parser.add_argument_group(title='Result output options')

    output_mode = parser_output.add_mutually_exclusive_group(required=True)

    output_mode.add_argument(
        '-o', '--output-file',
        help='Path to destination file for result output',
        metavar='/path/to/output.json', type=str)

    output_mode.add_argument(
        '-O', '--output-stdout',
        help='Print result output to stdout',
        action='store_true', default=False)

    parser_output.add_argument(
        '-r', '--results-version',
        help='Format version of result output data (default: %(default)i)',
        choices=[1], type=int, default=1)

    parser_output.add_argument(
        '-T', '--tag',
        help='Arbitrary text string for "tagging" the result output',
        metavar='"Nagios checks"', type=str, default='')

    # -------------------------------------------------------------------------
    parser_exec = parser.add_argument_group(title='Execution options')
    
    parser_exec.add_argument(
        '-t', '--timeout', dest='default_timeout',
        help='Default timeout for command execution (default: %(default)i)',
        metavar='SECONDS', type=int, default=60)

    parser_exec.add_argument(
        '-s', '--sleep', dest='sleep_time',
        help='Sleep time between execution of commands (default: %(default)i)',
        metavar='SECONDS', type=int, default=1)

    # -------------------------------------------------------------------------
    parser_misc = parser.add_argument_group(title='Miscellaneous options')

    parser_misc.add_argument(
        '-l', '--log-dest',
        help='Set application logging destination (default: %(default)s)',
        choices=('stream', 'syslog', 'none'), default='stream')

    parser_misc.add_argument(
        '-V', '--verbose', dest='log_verbose',
        help='Enable verbose application logging',
        action='store_true', default=False)

    parser_misc.add_argument(
        '-v', '--version',
        help='Display SnailEXEC version and exit',
        action='version', version=version)

    # -------------------------------------------------------------------------
    args = parser.parse_args()

    # Makes all empty command parameters iteratable
    if not args.commands:
        args.commands = []

    if not args.nrpe_files:
        args.nrpe_files = []

    if not args.json_files:
        args.json_files = []
    
    if not args.json_globs:
        args.json_globs = []

    if not args.nrpe_globs:
        args.nrpe_globs = []

    # Checks if any command paramters have been supplied
    if not (
        args.commands or args.nrpe_files or
        args.json_files or args.json_globs or args.nrpe_globs):

        parser.error('No argument for command execution was provided')

    return args

# -----------------------------------------------------------------------------
# Logging related code

class CustomNullHandler(logging.Handler):
    '''Custom null handler for logging, since it isn\'t available in 2.6'''

    def emit(self, record):
        pass


def log_init(destination, verbose):
    '''Configures application logging'''

    formatter = logging.Formatter(
        'snailexec: %(levelname)s - %(message)s')

    if verbose:
        logger.setLevel(logging.DEBUG)

    else:
        logger.setLevel(logging.INFO)

    if destination == 'stream':
        loghandler = logging.StreamHandler()

    elif destination == 'syslog':
        loghandler = logging.handlers.SysLogHandler(address='/dev/log')

    elif destination == 'none':
        loghandler = CustomNullHandler()

    loghandler.setFormatter(formatter)
    logger.addHandler(loghandler)

    return logger

# -----------------------------------------------------------------------------
# Command loading related code

def load_arg_command(command):
    '''Loads commands supplied with the command line argument "--command"'''

    logger.debug('Loading command "%s"' % str(command))

    command = {'name': command[0], 'command_string': command[1]}

    logger.debug('Loaded command: "%s"' % command)

    return command


def load_json_commands(json_file):
    '''Loads commands from a JSON file'''

    logger.info('Loading commands from JSON file "%s"' % json_file)

    try:
        with io.open(json_file, 'r', encoding='utf-8') as file_object:
            file_data = file_object.read()
            logger.debug('Contents of "%s": "%s"' % (json_file, file_data))

            json_data = json.loads(file_data)

    except IOError as error_msg:
        logger.error('Failed to open file "%s": "%s"' % (json_file, error_msg))
        return []

    except ValueError as error_msg:
        logger.error(
            'Failed to load JSON data from file "%s": "%s"'
            % (json_file, error_msg))

        return []

    except Exception as error_msg:
        logger.error(
            'Failed to load JSON from file "%s" due to unknown error: "%s"'
            % (json_file, error_msg))

        return []

    logger.debug('Extracting commands from JSON file "%s"' % json_file)

    if not isinstance(json_data, list):
        logger.error(
            'Data in JSON file "%s" was not provided as a list' % json_file)

        return []

    commands = []

    for index, value in enumerate(json_data):
        logger.debug(
            'Checking required parameters for index %i and value "%s"'
            % (index, str(value)))

        try:
            name = value.get('name')
            command_string = value.get('command')
            timeout = value.get('timeout')

            if not name or not command_string:
                logger.error(
                    'The "name" and/or "command" parameter was not '
                    'provided for index %i in JSON file "%s": "%s"'
                    % (index, json_file, str(value)))

                continue

            name = str(name)
            command_string = str(command_string)

            command = {'name': name, 'command_string': command_string}

            if timeout:
                timeout = int(timeout)
                command['timeout'] = timeout

            commands.append(command)

        except Exception as error_msg:
            logger.error(
                'Failed to load command for index %i in JSON file "%s": "%s"'
                % (index, json_file, error_msg))

            continue

    logger.debug(
        'Loaded %i commands from JSON file "%s": "%s"'
        % (len(commands), json_file, str(commands)))

    return commands


def load_nrpe_commands(nrpe_file):
    '''Loads commands from a NRPE configuration file'''

    logger.info('Loading commands from NRPE configuration "%s"' % nrpe_file)

    try:
        with io.open(nrpe_file, 'r', encoding='utf-8') as file_object:
            file_data = file_object.readlines()

            logger.debug('Contents of "%s": "%s"' % (nrpe_file, file_data))

    except IOError as error_msg:
        logger.error('Failed to open file "%s": "%s"' % (nrpe_file, error_msg))
        return []

    except Exception as error_msg:
        logger.error(
            'Failed to load NRPE configuration "%s" due to unknown error: "%s"'
            % (nrpe_file, error_msg))

        return []

    logger.debug('Loading commands from NRPE configuration "%s"' % nrpe_file)

    commands = []

    command_pattern = re.compile(r'^command\[(?P<name>.*)\]=(?P<command>.*)')
    remote_arg_pattern = re.compile(r'\$ARG\d+\$')

    for line, data in enumerate(file_data):
        try:
            data = data.strip()

            logger.debug('Checking line %i with data "%s"' % (line, str(data)))

            command = command_pattern.search(data)

            if not command:
                logger.debug('Line %i did not match command pattern' % line)
                continue

            logger.debug(
                'Line %i contained command - checking for remote arguments'
                % line)

            contains_remote_args = remote_arg_pattern.search(data)

            if contains_remote_args:
                logger.error(
                    'Command "%s" includes remotely supplied arguments'
                    % str(data))

                continue

            name = command.group('name')
            command_string = command.group('command')

            logger.debug(
                'Adding command with name "%s" and command "%s" to commands'
                % (name, command_string))

            commands.append({'name': name, 'command_string': command_string})

        except Exception as error_msg:
            logger.error(
                'Failed to load command from line %i in "%s": "%s"'
                % (line, nrpe_file, error_msg))

    logger.debug(
        'Loaded %i commands from NRPE configuration "%s": "%s"'
        % (len(commands), nrpe_file, str(commands)))

    return commands

# -----------------------------------------------------------------------------
# Command execution related code

def execute_command(**kwargs):
    '''Executes supplied commands in the "platform default" shell'''

    command_dict = kwargs.get('command_dict')
    sleep_time = kwargs.get('sleep_time')
    default_timeout = kwargs.get('default_timeout')
    results_version = kwargs.get('results_version')

    name = command_dict.get('name')
    command_string = command_dict.get('command_string')
    timeout = command_dict.get('timeout', default_timeout)

    logger.debug(
        'Executing "%s" with command string "%s", '
        '%i seconds of timeout, %i seconds of sleep time and result version %i'
        % (name, command_string, timeout, sleep_time, results_version))

    start_time = time.time()

    try:
        timeout_counter = timeout
        
        shell_exec = subprocess.Popen(
            command_string, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Checks if command execution is finished
        while shell_exec.poll() is None and timeout_counter:
            timeout_counter = timeout_counter - 1
            time.sleep(1)

        end_time = time.time()
        exec_time = end_time - start_time

        if not timeout_counter:
            msg = 'Command "%s" timed out after %i seconds' % (name, timeout)
            logger.error(msg)

            logger.debug('Sleeping for %i seconds before return' % sleep_time)
            time.sleep(sleep_time)

            return {
                'name': name, 'stdout': '',
                'stderr': '', 'exit_code': 1,
                'start_time': start_time, 'end_time': end_time,
                'exec_time': exec_time, 'status': 'ERROR', 'msg': msg}

        # Extracts the result data
        output = shell_exec.communicate()
        exit_code = shell_exec.returncode

        stdout = output[0]
        stderr = output[1]

        logger.debug('Decoding stdout and stderr as UTF-8')

        stdout = stdout.decode('utf-8', 'ignore')
        stderr = stderr.decode('utf-8', 'ignore')

        result = {
            'name': name, 'stdout': stdout,
            'stderr': stderr,'exit_code': exit_code,
            'start_time': start_time, 'end_time': end_time,
            'exec_time': exec_time, 'status': 'OK', 'msg': ''}

        logger.debug('Result of command "%s": "%s"' % (name, str(result)))

        logger.debug('Sleeping for %i seconds before return' % sleep_time)
        time.sleep(sleep_time)

        return result

    except Exception as error_msg:
        msg = (
            'Execution of command "%s" failed due to unknown issue: "%s"'
            % (name, error_msg)) 

        logger.error(msg)

        end_time = time.time()
        exec_time = end_time - start_time

        logger.debug('Sleeping for %i seconds before return' % sleep_time)
        time.sleep(sleep_time)

        return {
            'name': name, 'stdout': '',
            'stderr': '', 'exit_code': 1,
            'start_time': start_time, 'end_time': end_time,
            'exec_time': exec_time, 'status': 'ERROR', 'msg': msg}

# -----------------------------------------------------------------------------
# Main function related code

@json_guarded
def main():
    '''Main application function'''

    # Parses commandline arguments
    args = parse_args(description, version, developers, license) 

    # Configures application logging
    global logger
    logger = log_init(args.log_dest, args.log_verbose)

    try:
        user = getpass.getuser()

    except:
        user = 'UNKNOWN'

    logger.debug(
        'SnailEXEC has been started by user "%s" with arguments: "%s"'
        % (user, str(args)))

    start_time = int(time.time())

    # Command extraction from provided parameters
    commands = []

    for command in args.commands:
        commands.append(load_arg_command(command))

    for json_file in args.json_files:
        commands.extend(load_json_commands(json_file))

    for nrpe_file in args.nrpe_files:
        commands.extend(load_nrpe_commands(nrpe_file))

    for json_glob in args.json_globs:
        for json_file in json_glob:
            commands.extend(load_json_commands(json_file))

    for nrpe_glob in args.nrpe_globs:
        for nrpe_file in nrpe_glob:
            commands.extend(load_nrpe_commands(nrpe_file))

    if not commands:
        exit_program(
            msg='Could not load any commands for execution',
            tag=args.tag, output_file=args.output_file)

    # Executes loaded commands and returns the results
    results = []

    for command in commands:
        results.append(
            execute_command(
                command_dict=command,
                sleep_time=args.sleep_time,
                default_timeout=args.default_timeout,
                results_version=args.results_version))

    # Exits the program
    end_time = int(time.time())
    exec_time = end_time - start_time

    start_date = time.ctime(start_time)
    end_date = time.ctime(end_time)

    output_message = (
        'Job started at %s finished at %s after %i seconds of work'
        % (start_date, end_date, exec_time))

    exit_program(
        status='OK', msg=output_message, tag=args.tag,
        results=results, output_file=args.output_file)


if __name__ == '__main__':
    main()
