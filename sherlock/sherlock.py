import os
import ssl
from typing import List

import asyncio
import httpx

import re

from sherlock.result import QueryStatus, QueryResult
from sherlock.sites import SitesInformation


class Sherlock:
    """
    An async impl of sherlock for embedded usage.
    """

    def __init__(self, path):
        sites = SitesInformation(
            os.path.join(path, "sherlock", "resources", "data.json")
        )
        self.site_data = {}
        for site in sites:
            self.site_data[site.name] = site.information

        self.timeout = 15

    async def request(self, username: str) -> List:
        self.underlying_session: httpx.AsyncClient = httpx.AsyncClient()
        results = await self._request(username)
        response: List = []
        for website_name in results:
            dictionary = results[website_name]
            try:
                if dictionary.get("status").status == QueryStatus.CLAIMED:
                    response.append(dictionary["url_user"])
            except AttributeError:
                continue

        await self.underlying_session.aclose()

        return response

    async def _request(self, username: str):
        # Results from analysis of all sites
        results_total = {}
        iters = []
        # First create futures for all requests. This allows for the requests to run in parallel
        for social_network, net_info in self.site_data.items():

            async def site_request(social_network, net_info):
                # Results from analysis of this specific site
                results_site = {}

                # Record URL of main site
                results_site["url_main"] = net_info.get("urlMain")

                # A user agent is needed because some sites don't return the correct
                # information since they think that we are bots (Which we actually are...)
                headers = {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0",
                }

                if "headers" in net_info:
                    # Override/append any extra headers required by a given site.
                    headers.update(net_info["headers"])

                # URL of user on site (if it exists)
                url = net_info["url"].format(username)

                # Don't make request if username is invalid for the site
                regex_check = net_info.get("regexCheck")
                if regex_check and re.search(regex_check, username) is None:
                    # No need to do the check at the site: this user name is not allowed.
                    results_site["status"] = QueryResult(
                        username, social_network, url, QueryStatus.ILLEGAL
                    )
                    results_site["url_user"] = ""
                    results_site["http_status"] = ""
                    results_site["response_text"] = ""
                else:
                    # URL of user on site (if it exists)
                    results_site["url_user"] = url
                    url_probe = net_info.get("urlProbe")
                    if url_probe is None:
                        # Probe URL is normal one seen by people out on the web.
                        url_probe = url
                    else:
                        # There is a special URL for probing existence separate
                        # from where the user profile normally can be found.
                        url_probe = url_probe.format(username)

                    if (
                        net_info["errorType"] == "status_code"
                        and net_info.get("request_head_only", True) == True
                    ):
                        # In most cases when we are detecting by status code,
                        # it is not necessary to get the entire body:  we can
                        # detect fine with just the HEAD response.
                        request_method = self.underlying_session.head
                    else:
                        # Either this detect method needs the content associated
                        # with the GET response, or this specific website will
                        # not respond properly unless we request the whole page.
                        request_method = self.underlying_session.get

                    if net_info["errorType"] == "response_url":
                        # Site forwards request to a different URL if username not
                        # found.  Disallow the redirect so we can capture the
                        # http status from the original URL request.
                        allow_redirects = False
                    else:
                        # Allow whatever redirect that the site wants to do.
                        # The final result of the request will be what is available.
                        allow_redirects = True

                    # Default for Response object if some failure occurs.
                    response = None

                    error_context = "General Unknown Error"
                    expection_text = None
                    r = None
                    try:
                        response = r = await request_method(
                            url=url_probe,
                            headers=headers,
                            follow_redirects=allow_redirects,
                            timeout=self.timeout,
                        )
                        if response.status_code:
                            # Status code exists in response object
                            error_context = None
                    except httpx.HTTPError as errh:
                        error_context = "HTTP Error"
                        expection_text = str(errh)
                    except httpx.ProxyError as errp:
                        error_context = "Proxy Error"
                        expection_text = str(errp)
                    except (httpx.ConnectTimeout, httpx.ConnectError) as errc:
                        error_context = "Error Connecting"
                        expection_text = str(errc)
                    except httpx.TimeoutException as errt:
                        error_context = "Timeout Error"
                        expection_text = str(errt)
                    except ssl.SSLCertVerificationError:
                        error_context = "Unknown Error"
                        expection_text = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'discuss.atom.io'. (_ssl.c:1129)"

                    error_text = error_context

                    # Store request response in future
                    net_info["request_future"] = response

                    # Retrieve other site information again
                    url = results_site.get("url_user")
                    status = results_site.get("status")
                    if status is not None:
                        # We have already determined the user doesn't exist here
                        return

                    error_type = net_info["errorType"]

                    # Get response time for response of our request.
                    try:
                        response_time = r.elapsed
                    except AttributeError:
                        response_time = None

                    # Attempt to get request information
                    try:
                        http_status = r.status_code
                    except:
                        http_status = "?"
                    try:
                        response_text = r.text.encode(r.encoding)
                    except:
                        response_text = ""

                    if error_text is not None:
                        result = QueryResult(
                            username,
                            social_network,
                            url,
                            QueryStatus.UNKNOWN,
                            query_time=response_time,
                            context=error_text,
                        )
                    elif error_type == "message":
                        # error_flag True denotes no error found in the HTML
                        # error_flag False denotes error found in the HTML
                        error_flag = True
                        errors = net_info.get("errorMsg")
                        # errors will hold the error message
                        # it can be string or list
                        # by insinstance method we can detect that
                        # and handle the case for strings as normal procedure
                        # and if its list we can iterate the errors
                        if isinstance(errors, str):
                            # Checks if the error message is in the HTML
                            # if error is present we will set flag to False
                            if errors in r.text:
                                error_flag = False
                        else:
                            # If it's list, it will iterate all the error message
                            for error in errors:
                                if error in r.text:
                                    error_flag = False
                                    break
                        if error_flag:
                            result = QueryResult(
                                username,
                                social_network,
                                url,
                                QueryStatus.CLAIMED,
                                query_time=response_time,
                            )
                        else:
                            result = QueryResult(
                                username,
                                social_network,
                                url,
                                QueryStatus.AVAILABLE,
                                query_time=response_time,
                            )
                    elif error_type == "status_code":
                        # Checks if the status code of the response is 2XX
                        if not r.status_code >= 300 or r.status_code < 200:
                            result = QueryResult(
                                username,
                                social_network,
                                url,
                                QueryStatus.CLAIMED,
                                query_time=response_time,
                            )
                        else:
                            result = QueryResult(
                                username,
                                social_network,
                                url,
                                QueryStatus.AVAILABLE,
                                query_time=response_time,
                            )
                    elif error_type == "response_url":
                        # For this detection method, we have turned off the redirect.
                        # So, there is no need to check the response URL: it will always
                        # match the request.  Instead, we will ensure that the response
                        # code indicates that the request was successful (i.e. no 404, or
                        # forward to some odd redirect).
                        if 200 <= r.status_code < 300:
                            result = QueryResult(
                                username,
                                social_network,
                                url,
                                QueryStatus.CLAIMED,
                                query_time=response_time,
                            )
                        else:
                            result = QueryResult(
                                username,
                                social_network,
                                url,
                                QueryStatus.AVAILABLE,
                                query_time=response_time,
                            )
                    else:
                        # It should be impossible to ever get here...
                        raise ValueError(
                            f"Unknown Error Type '{error_type}' for "
                            f"site '{social_network}'"
                        )

                    # Save status of request
                    results_site["status"] = result

                    # Save results from request
                    results_site["http_status"] = http_status
                    results_site["response_text"] = response_text

                    # Add this site's results into final dictionary with all of the other results.
                    results_total[social_network] = results_site

            # For loopy boy
            iters.append(site_request(social_network, net_info))

        await asyncio.gather(*iters)

        return results_total

    async def get_response(self, request_future):

        # Default for Response object if some failure occurs.
        response = None

        error_context = "General Unknown Error"
        expection_text = None
        try:
            response = request_future
            if response.status_code:
                # Status code exists in response object
                error_context = None
        except httpx.HTTPError as errh:
            error_context = "HTTP Error"
            expection_text = str(errh)
        except httpx.ProxyError as errp:
            error_context = "Proxy Error"
            expection_text = str(errp)
        except (httpx.ConnectTimeout, httpx.ConnectError) as errc:
            error_context = "Error Connecting"
            expection_text = str(errc)
        except httpx.TimeoutException as errt:
            error_context = "Timeout Error"
            expection_text = str(errt)
        except ssl.SSLCertVerificationError:
            error_context = "Unknown Error"
            expection_text = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'discuss.atom.io'. (_ssl.c:1129)"

        return response, error_context, expection_text
