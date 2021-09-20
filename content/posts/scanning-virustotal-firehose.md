---
title: "Scanning VirusTotal's firehose"
date: 2021-09-20T09:22:42+02:00
draft: false
---

Let's say one of your adversaries is known for using a given malware family, a custom or COTS one. Even if the coverage would be extremely biaised and limited, wouldn't it be a shame to not track each and every samples uploaded on VirusTotal?

At $WORK, we are lucky to have access to the [Virus Total feeds/file API](https://developers.virustotal.com/reference#files-2). This API endpoint is the firehose of VirusTotal: It allows download each sample submitted to VT in pseudo real-time. The feed is unfiltered (we are not talking about [VT's LiveHunt feature](https://support.virustotal.com/hc/en-us/articles/360001315437-Livehunt)) so the volume is HUGE.

We set the crazy objective to **extract and push IOC in real-time for a given malware family submitted on VirusTotal**. For this blog post, as an example, we will focus on Cobalt Strike.

The steps are:

![Steps to scan VT](/images/6ba639ccc85872aaf5be9fe0b11ecd7acec0a24f.png)

1. Download each sample submitted
1. Apply Yara rules focusing on the malware families we are caring about
1. Automatically extract C2 configuration
1. Disseminate IOC

Initially, we used our on-premises infrastructure with 2-3 servers. Quickly, the operational maintenance killed us:
- Our [Celery](https://github.com/celery/celery/) cluster was regularly KO.
- Everything had to be very carefully tuned (memory limits, batch size, timeout, retries), we were constantly juggling with the balance between completeness, stability and speed.
- The addition of an under-performing Yara rule could break the platform.
- It was also not a good use of our computing resources as VT's activity is not uniform across the day: our servers were under-used most of the day while overloaded during the peaks.

## Going Serverless

Taking a step back, it jumped out at us that this was a textbook example for a Serverless architecture. It was easy to refactor our on-prem code into self-contained functions and glue them together with SQS:

![AWS Serverless Architecture for scanning VirusTotal feed](/images/70118f2f83f206d1a258d162d766b5cfd165765c.png)

The platform has been running smoothly for 18 months, and from an operational point of view, we love it:
- The scalability of the platform allowed to not mind anymore about the performance of each rule: we can add our Yara rules quite freely instead of cherry-picking and evaluating carefully each addition.
- The whole retry mechanism is handled by SQS.
- Adding a new dissector is as easy as plugging a new Lambda function to the SNS topic.
- Everything is decoupled, it is easy to update one part without touching the rest
- Each new release of libyara increases its performance and it is directly correlated to the execution duration's average.
- Everything is instrumented, we learned to love the AWS Monitoring Console.

## Performance Stats

For those who like numbers, here is a screenshot for the activity of the last 6 months:

![Invocations, duration, concurrent execs and error rate](/images/36e700b5eb8b36a40085e88a7ba14eac19aba702.png)

In average:
- A batch of samples is scanned in less than 30s
- There is always 45 Lambda functions running at a given time
- 97% of the executions are successful
- We send 150 samples per minute (before deduplication) to dissectors 

# CobaltStrike

![Mailbox full of BEACONs](/images/817e356268d1e7620ee8746d77fa5aee336028bc.png)

We are using [CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser) from Sentinel One to parse the beacons. The JSON output is sent to our Splunk instance from a threat hunting perspective to implement alerting for things like:
- Given Watermark identifiers
- Pattern in the C2 domain
- Non-standard values for some fields
- Use of some options or specific malleable profile

Currently, there is no automatic pipeline to push the IOC into a DenyList as it is not uncommon to see trolling BEACONs using legitimate and "assumed safe" domains. To mitigate that, we plan to have a kind of Slack bot to make us approve manually each entry.

