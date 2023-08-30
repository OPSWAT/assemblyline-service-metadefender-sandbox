import json
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT


FINAL_VERDICT_HEURISTIC_ID = {
    'benign': 1,
    'informational': 3,
    'unknown': 5,
    'suspicious': 7,
    'likely_malicious': 9,
    'malicious': 11
}

SIGNALS_HEURISTIC_ID = {
    'benign': 2,
    'informational': 4,
    'unknown': 6,
    'suspicious': 8,
    'likely_malicious': 10,
    'malicious': 12
}


def parse_compact_result(report, report_id, flow_id):
    tags = []
    for tag in report.get("allTags", []):
        tags.append(tag.get("tag", {}).get("name"))

    magic = None
    resources = report.get("resources", {})
    for resource_key, resource in resources.items():
        if "submitName" in resource:
            magic = resource.get("mediaType",{}).get("string")

    mitre_dict = {}
    for signal_group in report.get("allSignalGroups",[]):
        for mitre_technique in signal_group.get("allMitreTechniques", []):
            tactic = mitre_technique.get("relatedTactic", {}).get("name", "")
            technique = mitre_technique.get("name", "")
            mitre_dict.setdefault(tactic, [])
            mitre_dict[tactic].append(technique)

    mitre_rows = []
    for mitre_tactic, mitre_technique in mitre_dict.items():
        mitre_rows.append(f"{mitre_tactic}: {', '.join(mitre_technique)}")

    extracted_result = {
        "Verdict": report.get("finalVerdict",{}).get("verdict", "UNKNOWN"),
        "Name": report.get("file", {}).get("name"),
        "File Magic": magic,
        "SHA-256": report.get("file", {}).get("hash"),
        "Report ID": report_id,
        "Submission ID": flow_id,
        "Submission Date": report.get("created_date"),
        "Tags": tags,
        "MITRE Techniques": mitre_rows
    }
    return extracted_result


def process_allSignalGroups(result_section, all_signal_groups):
    #  Add subsection: Signal group, MITRE ATT&CK and YARA rule as tag
    for signalgroup in all_signal_groups:

        signalgroup_description = signalgroup.get("description", "")
        signal_readables = [signal.get("signalReadable") for signal in signalgroup.get("signals")]

        #  Add signal group as subsection
        signal_verdict = signalgroup.get("verdict", {}).get('verdict', 'UNKNOWN')

        if "allMitreTechniques" in signalgroup and len(signalgroup.get("allMitreTechniques",[])) > 0:
            for mitre in signalgroup.get("allMitreTechniques",[]):
                signalgroup_mitre_rs = ResultSection(signalgroup_description,
                        body_format=BODY_FORMAT.TEXT,
                        body=", \n".join(signal_readables))
                signalgroup_mitre_rs.set_heuristic(SIGNALS_HEURISTIC_ID[signal_verdict.lower()], signature= mitre.get("name",None), attack_id=mitre.get("ID", None))
                result_section.add_subsection(signalgroup_mitre_rs)
        else:
            signalgroup_rs =  ResultSection(signalgroup_description,
                        body_format=BODY_FORMAT.TEXT,
                        body=", \n".join(signal_readables))
            signalgroup_rs.set_heuristic(SIGNALS_HEURISTIC_ID[signal_verdict.lower()])
            result_section.add_subsection(signalgroup_rs)

        # If YARA, add YARA rule tag
        if "YARA rule" in signalgroup_description:
            for signal in signalgroup.get("signals", []):
                signalReadable = signal.get("signalReadable", "")
                if "Matched YARA rule" in signalReadable:
                    result_section.add_tag("file.rule.yara", signal.get("additionalInfo"))

        if "Document contains OLE streams (VBA macros)" in signalgroup_description:
            result_section.add_tag("technique.macro", "Contains VBA Macro(s)")

    return result_section


def process_iocs(result_section, iocs):
    def process_ioc(key, target_tag):
        if key in iocs:
            for element in iocs[key]:
                if 'data' in element:
                    return (target_tag, element['data'])
        return None

    tags = []
    if email := process_ioc('email', 'network.email.address'):
        tags.append(email)
    if url := process_ioc('url', 'network.static.uri'):
        tags.append(url)
    if ip := process_ioc('ip', 'network.static.ip'):
        tags.append(ip)
    if domain := process_ioc('domain', 'network.static.domain'):
        tags.append(domain)

    for tag in tags:
        result_section.add_tag(tag[0],tag[1])

    return result_section


def process_allOsintTags(result_section, all_osint_tags):
    for allOsintTag in all_osint_tags:
        tag = allOsintTag.get('tag', {})
        verdict = tag.get('verdict', {}).get('verdict', 'UNKNOWN')
        if verdict in ['MALICIOUS', 'LIKELY_MALICIOUS', 'SUSPICIOUS'] and 'name' in tag:
            result_section.add_tag('av.virus_name',tag['name'])
            for synonym in tag.get('synonyms'):
                result_section.add_tag('av.virus_name', synonym)
    return result_section


def process_resources(result_section, resources):
    for resource_key, resource in resources.items():
        if len(resource.get('results', [])) > 0:
            for result in resource.get('results', []):
                data =  result.get('data', {})
                if threat_name := data.get('threat_name'):
                    result_section.add_tag('av.virus_name', threat_name)
                if family := data.get('malware_family'):
                    result_section.add_tag('attribution.family', family)
                if category := data.get('malware_type'):
                    for cat in category:
                        result_section.add_tag('attribution.category', cat)

        if 'metaData' in resource:
            metadata = resource['metaData']
            if 'pdf:docinfo:modified' in metadata:
                result_section.add_tag('file.pdf.date.modified', metadata['pdf:docinfo:modified'])
            if 'dc:title' in metadata:
                result_section.add_tag('file.ole.summary.title', metadata['dc:title'])
            if 'dc:creator' in metadata:
                print("CREATOR!")
                result_section.add_tag('file.ole.summary.author', metadata['dc:creator'])
            if 'Company' in metadata:
                result_section.add_tag('file.ole.summary.company', metadata['Company'])
            if 'dcterms:created' in metadata:
                result_section.add_tag('file.ole.summary.create_time', metadata['dcterms:created'])
            if 'meta:print-date' in metadata:
                result_section.add_tag('file.ole.summary.last_printed', metadata['meta:print-date'])
            if 'meta:last-author' in metadata:
                result_section.add_tag('file.ole.summary.last_saved_by', metadata['meta:last-author'])
            if 'dc:subject' in metadata:
                result_section.add_tag('file.ole.summary.subject', metadata['dc:subject'])

        if 'extendedData' in resource:
            extended_data = resource['extendedData']
            if 'imphash' in extended_data:
                result_section.add_tag('file.pe.imports.imphash', extended_data['imphash'])
            if 'language' in extended_data:
                result_section.add_tag('file.pe.resources.language', extended_data['language'])
            if 'richHeader' in extended_data:
                result_section.add_tag('file.pe.rich_header.hash', extended_data['richHeader'].get('checksum',''))
            if 'verinfo' in extended_data:
                for verinfo in extended_data['verinfo']:
                    if verinfo.get("name","") == "OriginalFilename":
                        result_section.add_tag('file.pe.versions.filename',verinfo.get("value",""))
            if 'importsEx' in extended_data:
                for importEx in extended_data['importsEx']:
                    if importEx.get('module', {}).get('suspicious', False):
                        result_section.add_tag('file.pe.imports.suspicious',importEx.get('module', {}).get('name',''))
            if 'exports' in extended_data:
                for exports in extended_data['exports']:
                    result_section.add_tag('file.pe.exports.module_name',exports.get('name', ''))

    return result_section


def parse_report(report, report_id, flow_id):
    compact_result = parse_compact_result(report, report_id, flow_id)
    verdict_rs = ResultSection('OPSWAT Filescan Sandbox result',
                    body_format=BODY_FORMAT.KEY_VALUE,
                    body=json.dumps(compact_result))

    final_verdict = report.get("finalVerdict",{}).get("verdict", "UNKNOWN")
    verdict_rs.set_heuristic(FINAL_VERDICT_HEURISTIC_ID[final_verdict.lower()])

    verdict_rs = process_allSignalGroups(verdict_rs, report.get("allSignalGroups", []))
    verdict_rs = process_iocs(verdict_rs, report.get("iocs", {}))
    verdict_rs = process_allOsintTags(verdict_rs, report.get("allOsintTags", []))
    verdict_rs = process_resources(verdict_rs, report.get("resources", {}))
    return verdict_rs


def result_parser(res, response):
    if not response:
        return res

    for report_id, report in response.get("reports", {}).items():
        res.add_section(parse_report(report, report_id, response.get("flowId","")))

    return res
