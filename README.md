SnailEXEC
=========
###### _Execute shell commands and output the results to JSON for later use_

Overview
========
The script executes shell commands specified as command line arguments, JSON files or NRPE command definitions.  
The "results" of executed commands are output to JSON and can be saved to file or printed to stdout.  

Once complete, the results can be transfered to a remote system with HTTP/FTP/sneaker net/... and be analyzed with *something* like [check_snailexec](https://github.com/Doctor-love/check_snailexec).  

Installation
============
The script requires Python 2.7 or 2.6 with the "argparse" module installed.  
SnailEXEC has been tested on various UNIX-like systems and Windows 8.1.  

Example output
==============
Executing commands specified with command line arguments:  

```
$ ./snailexec.py --tag 'Nagios disk checks' \
    --command 'check_disk_root' '/usr/lib/nagios/plugins/check_disk -w "15" -c "5" -p "/"' \
    --command 'check_disk_boot' '/usr/lib/nagios/plugins/check_disk -w "25" -c "10" -p "/boot"' \
    --output-file "/path/to/remote/mount/results-$(hostname -f)-disk_checks.json"

$ cat "/path/to/remote/mount/results-$(hostname -f)-disk_checks.json"

{
    "status": "OK",
    "msg": "Job started at Sun Dec 20 12:33:58 2015 finished at Sun Dec 20 12:34:02 2015 after 4 seconds of work",
    "tag": "Nagios disk checks", "results_version": 1,
    "results": [
        {
            "status": "OK", "msg": "", "name": "check_disk_root",
            "stderr": "", "stdout": "DISK OK - free space: / 125759 MB (59% inode=95%);| /=85316MB;222380;222390;0;222395\n",
            "exec_time": 1.0018367767333984, "start_time": 1450611238.066903, "exit_code": 0, "end_time": 1450611239.06874

        },

        {
            "status": "OK", "msg": "", "name": "check_disk_boot",
            "stderr": "", "stdout": "DISK OK - free space: /boot 2413 MB (93% inode=99%);| /boot=178MB;2726;2741;0;2751\n",
            "exec_time": 1.0018720626831055, "start_time": 1450611240.069989, "exit_code": 0, "end_time": 1450611241.071861

        }

    ]

}
```

Executing commands from NRPE command definitions and e-mailing the results:

```
$ ./snailexec.py --tag 'NRPE checks' --nrpe-glob '/etc/nrpe/*.cfg' \
    --output-stdout | mail -s "NRPE checks - $(date)" 'monitoring-system@example.com'

snailexec: INFO - Loading commands from NRPE configuration "/etc/nrpe/custom_checks.cfg"
snailexec: ERROR - Command "command[check_ping]=/usr/lib/nagios/plugins/check_ping -H '$ARG1$'" includes remotely supplied arguments
snailexec: INFO - Loading commands from NRPE configuration "/etc/nrpe/system_checks.cfg"
```

Executing commands from JSON file:  
```
$ cat "/path/to/commands.json"

[
    {
        "name": "check_gdns_alive",
        "command": "/usr/lib/nagios/plugins/check_ping -H 8.8.8.8 -w 30,3% -c 40,4%",
        "timeout": 15

    },

    {
        "name": "check_timeout",
        "command": "/bin/sleep 5s",
        "timeout": 3

    }

]

$ ./snailexec.py --json "/path/to/commands.json" --output-file "test_output_2.json"

snailexec: INFO - Loading commands from JSON file "misc/command_example.json"
snailexec: ERROR - Command "check_timeout" timed out after 3 seconds

```
