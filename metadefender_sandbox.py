from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT

import json
import base64
import metadefender_sandbox_result

import time
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


POLLING_FILTERS = [
    "filter=general",
    "filter=finalVerdict",
    "filter=allTags",
    "filter=overallState",
    "filter=taskReference",
    "filter=subtaskReferences",
    "filter=allSignalGroups",
    "filter=o:all",
    "filter=iocs",
    "filter=f:all"
]

def requests_retry_session(
    retries=20, backoff_factor=2, status_forcelist=(500, 502, 503, 504), session=None
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


class MetaDefenderSandbox(ServiceBase):
    def __init__(self, config=None):
        super(MetaDefenderSandbox, self).__init__(config)
        self.api_key = self.config.get("api_key")
        self.host = self.config.get("host")
        self.headers = {}
        self.poll_interval = self.config.get("poll_interval")
        self.timeout = self.config.get("timeout")

    def start(self):
        # ==================================================================
        # On Startup actions:
        #   Your service might have to do some warming up on startup to make things faster

        self.log.info(f"start() from {self.service_attributes.name} service called")
        self.log.debug("MetaDefender Sandbox service started")


    def post_sample(self, request: ServiceRequest, url=None, file_path=None):
        if not url and not file_path:
            self.log.warning(f"There is no URL or file path!")
            self.log.debug(f"URL: {url}, file path {file_path}")
            return {}

        data = {}

        # Send file or URL for scan
        if request.get_param("description"):
            data["description"] = request.get_param("description")
        if request.get_param("password"):
            data["password"] = request.get_param("password")
        if request.get_param("is_private"):
            data["is_private"] = (str(request.get_param("is_private"))).lower()

        flow_id = None
        if url:
            data["url"] = url
            with requests_retry_session() as session:
                response = session.post(
                    f"{self.host}/api/scan/url",
                    headers=self.headers,
                    verify=False,
                    timeout=120,
                    data=data,
                )
                assert response.status_code == requests.codes.ok
                flow_id = (response.json()).get("flow_id")
        elif file_path:
            with requests_retry_session() as session:
                with open(file_path, "rb") as target_file:
                    response = session.post(
                        f"{self.host}/api/scan/file",
                        headers=self.headers,
                        verify=False,
                        timeout=120,
                        data=data,
                        files={"file": target_file},
                    )
                    assert response.status_code == requests.codes.ok
                    flow_id = (response.json()).get("flow_id")
        else:
            self.log.error(f"There is no URL or file path!")
            self.log.debug(f"URL: {url}, file path {file_path}")

        if not flow_id:
            self.log.error(f"flow_id is missing!")
            self.log.debug(f"flow_id is missing: {flow_id}")
            return {}

        # Polling the results
        self.log.info(f"Start to polling the following id: {flow_id}")

        filters_query = "&".join(POLLING_FILTERS)
        endpoint = f"{self.host}/api/scan/{flow_id}/report?{filters_query}"

        elapsed_time = 0
        poll_count = 0
        response = {}
        while elapsed_time <= self.timeout:
            poll_count += 1
            self.log.debug(f"Elapsed time: {elapsed_time}, polling count: {poll_count}")

            with requests_retry_session(retries=1) as session:
                response = session.get(
                    endpoint, headers=self.headers, verify=False, timeout=120
                )
                assert response.status_code == requests.codes.ok

            if (response.json()).get("allFinished", False):
                return response.json()

            if elapsed_time + self.poll_interval > self.timeout:
                time.sleep(self.timeout-elapsed_time)
                elapsed_time += self.timeout-elapsed_time
            else:
                time.sleep(self.poll_interval)
                elapsed_time += self.poll_interval

        self.log.warning(f"There was no result within max polling time!")
        self.log.debug(f"Elapsed time: {elapsed_time}, polling count: {poll_count}")
        self.log.debug(f"Last response: {response}")
        return {}


    def execute(self, request: ServiceRequest) -> None:
        # ==================================================================
        # Execute a request:
        #   Every time your service receives a new file to scan, the execute function is called
        #   This is where you should execute your processing code.
        #   For this example, we will only generate results ...
        # ==================================================================

        try:
            if request.get_param("api_key"):
                self.api_key=request.get_param("api_key")

            if request.get_param("poll_interval"):
                self.poll_interval=request.get_param("poll_interval")
            if not self.poll_interval:
                self.poll_interval = 2

            if request.get_param("timeout"):
                self.poll_interval=request.get_param("timeout")
            if not self.timeout:
                self.timeout = 60

            self.host = self.config.get("host")

            self.log.debug(f"The request has the following parameters: host: {self.host}, API-key:{self.api_key[0:5]}..., polling interval: {self.poll_interval} sec, timeout: {self.timeout} sec")

            assert self.host and self.api_key, "API-key or host is missing!"
            self.headers = {"X-Api-Key": self.api_key}

            assert self.poll_interval > 0 and self.timeout > 0, "Poll interval or timeout is not appropriate"
        except Exception as e:
            self.log.error(
                "No API key or Host found for MetaDefender Sandbox. Error: {e!r}"
            )
            raise e

        submitted_url = request.task.metadata.get('submitted_url', None)
        submitted_file = request.file_path

        response = {}
        try:
            if submitted_url:
                self.log.info("MetaDefender Sandbox start to scan a file")
                response = self.post_sample(request, url=submitted_url)
            elif submitted_file:
                self.log.info("MetaDefender Sandbox start to scan an URL")
                response = self.post_sample(request, file_path=submitted_file)
        except Exception as e:
            self.log.error(f"Error occurred when scan a file/URL: {e!r}")
            self.log.debug(f"Error occurred when scan a file/URL: {e!r}")

        # Create a result object where all the result sections will be saved to
        result = Result()

        if response:
            rejected = response.get("rejected_files", None)
            if rejected:
                for rejection in rejected:
                    rejection_result = ResultSection('MetaDefender Sandbox rejection',
                                                    body_format=BODY_FORMAT.KEY_VALUE,
                                                    body=json.dumps(rejection))
                    result.add_section(rejection_result)

            if response.get("reports", {}):
                result = metadefender_sandbox_result.result_parser(result, response)
            else:
                self.log.warning(f"There is no MetaDefender Sandbox reports.")

            report_link = f"{self.host}/uploads/{response.get('flowId')}"
            report_link_rs = ResultSection('MetaDefender Sandbox full report is available here:',
                body_format=BODY_FORMAT.URL,
                body=json.dumps({"name": "MetaDefender Sandbox report", "url": report_link}))
            result.add_section(report_link_rs)

        else:
            self.log.warning(f"There is no MetaDefender Sandbox response.")

        request.result = result
