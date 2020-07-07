# crowdstrike-oauth

Wrapper for Crowdstrike Oauth API, but a limited implementation of just a few endpoints..

The list_devices and list_devices_scroll, both seem to suffer from an upper bounds (150k)

Examples:

Instatiate class
```python
    cs = CrowdStrike()
```

List Devices
```python
    device_list = cs.list_devices_scroll()
    print(len(device_list))

Upload IOCs
```python
    iocs = [('domain', 'ningzhidata.com')]
    resp = cs.upload_ioc(iocs, share_level="white", expiration_days=90, source="SpiderLabs", description="https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/the-golden-tax-department-and-the-emergence-of-goldenspy-malware/")
``` 

Run Commands (RTR):
```python
    aids = ['aid1', 'aid2', '...']

    script_name = 'MyAwesomeScript' # you can use the API to get scripts, or get the name directly from the UI
    putfile1_name = 'MyPutFile1'  # in order to put files on systems, they have to be uploaded to the cloud.
    putfile2_name = 'MyPutFile2'

    batch_ids = cs.init_session(aids) # we have to create the sessions first
    run_cmds = [
        ('mkdir', '/Library/MyTempPath/'),
        ('cd', '/Library/MyTempPath/'),
        ('put', putfile1_name),
        ('cd', '/Library/LaunchDaemons/'),
        ('put', putfile2_name),
        ('runscript', '-CloudFile="{0}"'.format(script_name))
    ]
    for run_cmd in run_cmds:
        resp = cs.run_cmd(batch_ids, run_cmd[0], run_cmd[1], aids)
        pprint(resp)
```
