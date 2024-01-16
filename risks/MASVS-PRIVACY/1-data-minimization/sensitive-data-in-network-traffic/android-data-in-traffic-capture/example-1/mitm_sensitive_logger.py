from mitmproxy import http

SENSITIVE_STRINGS = ["dummyPassword", "sampleUser"]

def contains_sensitive_data(string):
    return any(sensitive in string for sensitive in SENSITIVE_STRINGS)

def process_flow(flow):
    url = flow.request.pretty_url
    request_headers = flow.request.headers
    request_body = flow.request.text
    response_headers = flow.response.headers if flow.response else "No response"
    response_body = flow.response.text if flow.response else "No response"

    if (contains_sensitive_data(url) or 
        contains_sensitive_data(request_body) or 
        any(contains_sensitive_data(header) for header in request_headers.values()) or
        any(contains_sensitive_data(header) for header in response_headers.values()) or
        contains_sensitive_data(response_body)):
        with open("sensitive_data.log", "a") as file:
            if flow.response:
                file.write(f"RESPONSE URL: {flow.request.pretty_url}\n")
                file.write(f"Response Headers: {flow.response.headers}\n")
                file.write(f"Response Body: {flow.response.text}\n\n")
            else:
                file.write(f"REQUEST URL: {flow.request.pretty_url}\n")
                file.write(f"Request Headers: {flow.request.headers}\n")
                file.write(f"Request Body: {flow.request.text}\n\n")
def request(flow: http.HTTPFlow):
    process_flow(flow)

def response(flow: http.HTTPFlow):
    process_flow(flow)

