# assemblyline-service-metadefender-sandbox

This repository is self-developed Assemblyline service which submits a file or a URL from Assemblyline4 to MetaDefender Sandbox (previously known as OPSWAT Filescan Sandbox), and after a successful scan its fetches and parses the result.

## Prerequirements

Using this integration it is necessary to have a MetaDefender Sandbox API-key. You can use the Activation Key that you received from your OPSWAT Sales Representative, and follow the instructions on the [License Activation page](https://docs.opswat.com/filescan/installation/license-activation) or you can create an API key on the [Community site](https://www.filescan.io/auth/signin) under API Key tab.

## Heuristics

The result contains two types of heuristic:

- __MetaDefender Sandbox verdict is _VERDICT___ : This is the final verdict of MetaDefender Sandbox and added as a ResultSection
- ___VERDICT_ threat indicators__: Comes from signal groups and added as a subsection

Heuristic score is the following:

| score | MetaDefender Sandbox verdict |
|------:|------------------------------|
| -1000 | BENIGN                       |
|   150 | NO THREAT                    |
|   299 | UNKNOWN                      |
|   500 | SUSPICIOUS                   |
|   850 | LIKELY MALICIOUS             |
|  1000 | MALICIOUS                    |

## Official documentation

Official, and more detailed documentation is available [here](https://docs.opswat.com/filescan/integrations/assemblyline-4).