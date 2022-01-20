---
title: "HOWTO use msticpy's process tree with Sysmon?"
date: 2022-01-20T06:22:42+02:00
Summary: This post introduce how to render msticpy's Process Tree with Sysmon telemetry.
---

[Jupyterthon 2021](https://infosecjupyterthon.com/introduction.html) was like a Christmas party for Blue teams. The brilliant minds of Microsoft made  convincing demos about their use of Jupyter Notebook and especially their msticpy Python module.

One of the candies is their Process Tree visualization function: you give a list of processes and you get a nice representation of its hierarchy:

![](/static/images/9dc9a604a23586b7b5d52f340aa070d0da7f23e3.png)

At $WORK, we are heavy user of Sysmon so we [contributed its support upstream](https://github.com/microsoft/msticpy/pull/267). Nonetheless, even though [all notebooks presented during the conference are available on Github](https://github.com/OTRF/infosec-jupyterthon/tree/master/workshops/2021), we were still missing a minimalistic example of ptree's usage.

So here is one for you:

```python
#!/usr/bin/env python
# coding: utf-8

import pandas as pd

from msticpy.data.data_providers import QueryProvider
from msticpy.sectools.proc_tree_builder import ProcSchema
from msticpy.nbtools import process_tree as ptree

host = "xxx"

spl = f'''search 
index=wineventlog-sysmon sourcetype="*Sysmon*" EventID=1 host={host} {host}
| sort 0 _time
| rename _time as UtcTime
| table UtcTime, Image, ProcessId, CommandLine, ParentImage, ParentProcessId, LogonId, ParentCommandLine, Computer, EventID
'''

splunk_prov = QueryProvider('Splunk')
splunk_prov.connect(host='splunk.server.local', username='xxx', password="xxx")

proc_df = splunk_prov.exec_query(spl)
proc_df.head()

proc_df["ProcessId"] = pd.to_numeric(proc_df.ProcessId)
proc_df["EventID"] = pd.to_numeric(proc_df.EventID)
proc_df["ParentProcessId"] = pd.to_numeric(proc_df.ParentProcessId)

proc_df["UtcTime"] = pd.to_datetime(proc_df.UtcTime, unit="s", utc=True)

p_tree_win = ptree.build_process_tree(proc_df)
ptree.plot_process_tree(p_tree_win)
```

And how to highlight specific cells in the rendering? Easy! Use the `legend_col` parameter as [clearly documented](https://msticpy.readthedocs.io/en/latest/visualization/ProcessTree.html?highlight=processtree#process-tree-plotting-syntax):

```python
proc_df["Interesting"] = (proc_df["Image"] == "C:\\WINDOWS\\System32\\rundll32.exe").astype(int)
p_tree_win = ptree.build_process_tree(proc_df)
ptree.plot_process_tree(p_tree_win, legend_col="Interesting")
```

Enjoy!

