from mitmproxy import http

# This data would come from another file and should be defined after identifying the data that is considered sensitive for this application.
# For example by using the Google Play Store Data Safety section.
SENSITIVE_DATA = {
    "precise_location_latitude": "37.7749",
    "precise_location_longitude": "-122.4194",
    "name": "John Doe",
    "email_address": "john.doe@example.com",
    "phone_number": "+11234567890",
    "credit_card_number": "1234 5678 9012 3456"
}

SENSITIVE_STRINGS = SENSITIVE_DATA.values()

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
        contains_sensitive_data(response_body)):
        with open("sensitive_data.log", "a") as file:
            if flow.response:
                file.write(f"RESPONSE URL: {url}\n")
                file.write(f"Response Headers: {response_headers}\n")
                file.write(f"Response Body: {response_body}\n\n")
            else:
                file.write(f"REQUEST URL: {url}\n")
                file.write(f"Request Headers: {request_headers}\n")
                file.write(f"Request Body: {request_body}\n\n")
def request(flow: http.HTTPFlow):
    process_flow(flow)

def response(flow: http.HTTPFlow):
    process_flow(flow)

